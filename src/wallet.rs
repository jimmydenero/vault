//! Wallets (#7440, #7490): a key the vault makes itself and never gives out, used only to sign a
//! token transfer it builds from structured fields, inside caps only the person on the vault's
//! machine sets. The decisions are pure functions here; `evm`, `solana` and `tron` encode and sign;
//! the daemon (`server`) reads the request, records the spend and the audit lines, and answers.
//!
//! **Chains and tokens.** The chains v1's agent wallets used (brennancheung/platform-ops
//! `Wallets.Chains`), each with a test network for a dry run: Ethereum (USDC, USDT) and Sepolia
//! (USDC); Solana (USDC, USDT) and Solana devnet (USDC); Tron (USDT) and Tron Nile (USDT).
//! Contracts, mints and decimals are chain_pay's `ChainPay.Assets`.
//!
//! **Caps** (`Caps`), set when the wallet is made and changed only with the recovery key, since
//! the socket can't tell the person from an agent (R23):
//! - `per_payment` and `daily` (rolling 24 hours), in US dollars: USDC and USDT count one for one;
//! - a fee cap per transaction, in the chain's own terms: Ethereum's `max_fee_per_gas` (wei per
//!   gas), Tron's `fee_limit` (sun), Solana's compute-unit price (micro-lamports per unit);
//! - a daily fee cap in the chain's own coin's smallest unit (wei, sun, lamports): the most the
//!   signed transactions of a rolling 24 hours could burn in fees, each counted at its worst case.
//!
//! **The ladder** (`ladder`, Ethereum only): the same transfer, at the same nonce, at rising fees,
//! so the relay can replace a payment that stalls while the vault is offline. Only one transaction
//! per nonce can mine, so a ladder can never pay twice. Each rung raises both fees by 12.5% (rounded
//! up, at least 1 wei), the least a node takes as a replacement (v1's `bump_fees`). At most
//! `MAX_LADDER` rungs, so its top is at most about 1.6 times the first fee; never above the
//! wallet's `max_fee_per_gas` or the caller's own `ladder_max_fee_per_gas`, whichever is lower (a
//! rung that would pass it isn't signed); and the worst case of the whole ladder counts against
//! the daily fee cap before anything is signed.
//!
//! **No ladder on Solana or Tron.** Neither has a nonce: two transactions of the same transfer at
//! different fees are two payments, and both can land. What makes one stop is its expiry (its
//! recent blockhash on Solana, about a minute or two; its `expiration` on Tron, at most 60 seconds
//! here). So the vault signs one transaction per request, and a payment that didn't land is signed
//! again, with a fresh blockhash or ref block, only once the first has expired; that new one counts
//! against the caps again (the vault can't see the chain, so it can't know the first didn't land).
//! On Tron a fee bump isn't needed anyway: there is no fee auction, and `fee_limit` is only a ceiling.
//!
//! **A replacement** counts once against the amount caps: on Ethereum, the same transfer at a
//! nonce already signed for in the last day, since only one of the two can mine (its fee counts only
//! for what it raises the worst case by); on Solana and Tron, the very same transaction asked for
//! again (signing is deterministic, so it is the same bytes and can land only once).
//!
//! **A cancel** (#7491; v1's owner's cancel, `Execution.cancel`), Ethereum only: a transfer of 0
//! ETH from the wallet to itself, 21,000 gas and no data, at the nonce of a payment it signed in
//! the last day, and at no other nonce. Whichever of the two mines takes the nonce, so if the
//! cancel does, nothing is paid. It moves no value and counts no amount; its fee is bounded by
//! `max_fee_per_gas` like any rung, its own ladder follows the payment ladder's bounds, and its
//! worst case counts against `daily_fees_wei` for what it raises that nonce's worst case by.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::VaultError;
use crate::secret::SecretValue;
use crate::{evm, solana, tron};

/// A day, in seconds: the window of the daily caps.
pub const DAY_SECS: u64 = 86_400;
/// The most rungs a ladder has.
pub const MAX_LADDER: usize = 4;
/// The gas a token transfer may be given: an ERC-20 `transfer` takes about 35,000 to 65,000.
pub const MIN_GAS_LIMIT: u64 = 21_000;
pub const MAX_GAS_LIMIT: u64 = 150_000;
/// Upper bounds on caps, against a typing slip: a million dollars a day; per transaction 10,000
/// gwei per gas, 1,000 TRX of `fee_limit`, 50 lamports per compute unit; a day's fees 1 ETH,
/// 10,000 TRX, 1 SOL.
pub const MAX_DAILY_MICROS: u64 = 1_000_000 * MICROS;
pub const MAX_FEE_PER_GAS_CAP: u64 = 10_000 * GWEI;
pub const MAX_DAILY_FEES: u64 = WEI_PER_ETH;
pub const MAX_FEE_LIMIT_CAP: u64 = 1_000 * SUN_PER_TRX;
pub const MAX_DAILY_FEES_SUN: u64 = 10_000 * SUN_PER_TRX;
pub const MAX_COMPUTE_UNIT_PRICE_CAP: u64 = 50_000_000;
pub const MAX_DAILY_FEES_LAMPORTS: u64 = LAMPORTS_PER_SOL;
/// The most spends a wallet remembers (a day's worth): further signing is refused until older
/// ones leave the window, so the vault file can't grow without end.
pub const MAX_SPENDS: usize = 500;
/// The longest `on_behalf_of` a caller may give for the audit log.
pub const MAX_LABEL_CHARS: usize = 128;

/// Dollars are kept in millionths (USDC's and USDT's own unit on every chain here).
pub const MICROS: u64 = 1_000_000;
pub const GWEI: u64 = 1_000_000_000;
pub const WEI_PER_ETH: u64 = 1_000_000_000_000_000_000;
pub const SUN_PER_TRX: u64 = 1_000_000;
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// The chains a wallet can be made for.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    /// Ethereum mainnet, chain id 1.
    Ethereum,
    /// Ethereum's Sepolia test network, chain id 11155111: test tokens with no value.
    Sepolia,
    /// Solana mainnet-beta.
    Solana,
    /// Solana's devnet: test tokens with no value.
    SolanaDevnet,
    /// Tron mainnet.
    Tron,
    /// Tron's Nile test network: test tokens with no value.
    TronNile,
}

/// How a chain's keys, addresses, transactions and fees work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// secp256k1, `0x` addresses, EIP-1559 transactions with a nonce; fees in wei.
    Evm,
    /// Ed25519, base58 addresses, a recent blockhash instead of a nonce; fees in lamports.
    Solana,
    /// secp256k1, base58check `T...` addresses, a ref block and an expiration; fees in sun.
    Tron,
}

impl Family {
    /// The chain's own coin, which pays its fees.
    pub fn coin(self) -> &'static str {
        match self {
            Family::Evm => "ETH",
            Family::Solana => "SOL",
            Family::Tron => "TRX",
        }
    }

    /// Its smallest unit's name, and how many decimals the coin has.
    pub fn fee_unit(self) -> &'static str {
        match self {
            Family::Evm => "wei",
            Family::Solana => "lamports",
            Family::Tron => "sun",
        }
    }

    pub fn coin_decimals(self) -> u32 {
        match self {
            Family::Evm => 18,
            Family::Solana => 9,
            Family::Tron => 6,
        }
    }

    /// An amount of fees in the smallest unit, as the coin: "0.0021 SOL".
    pub fn fee_text(self, units: u64) -> String {
        format!("{} {}", decimal(units as u128, self.coin_decimals()), self.coin())
    }
}

impl Chain {
    pub const ALL: [Chain; 6] = [Chain::Ethereum, Chain::Sepolia, Chain::Solana, Chain::SolanaDevnet, Chain::Tron, Chain::TronNile];

    pub fn label(self) -> &'static str {
        match self {
            Chain::Ethereum => "ethereum",
            Chain::Sepolia => "sepolia",
            Chain::Solana => "solana",
            Chain::SolanaDevnet => "solana_devnet",
            Chain::Tron => "tron",
            Chain::TronNile => "tron_nile",
        }
    }

    pub fn family(self) -> Family {
        match self {
            Chain::Ethereum | Chain::Sepolia => Family::Evm,
            Chain::Solana | Chain::SolanaDevnet => Family::Solana,
            Chain::Tron | Chain::TronNile => Family::Tron,
        }
    }

    /// An EVM chain's id (EIP-155); none on Solana or Tron.
    pub fn chain_id(self) -> Option<u64> {
        match self {
            Chain::Ethereum => Some(1),
            Chain::Sepolia => Some(11_155_111),
            _ => None,
        }
    }

    /// Whether its tokens have no value (a dry run).
    pub fn is_test(self) -> bool {
        matches!(self, Chain::Sepolia | Chain::SolanaDevnet | Chain::TronNile)
    }

    pub fn parse(text: &str) -> Result<Chain, VaultError> {
        Chain::ALL.into_iter().find(|chain| chain.label() == text).ok_or_else(|| {
            VaultError::BadRequest("chain is ethereum, solana or tron (or sepolia, solana_devnet or tron_nile for a dry run)".into())
        })
    }
}

/// The tokens a wallet pays in.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    #[serde(rename = "USDC")]
    Usdc,
    #[serde(rename = "USDT")]
    Usdt,
}

impl Token {
    pub fn label(self) -> &'static str {
        match self {
            Token::Usdc => "USDC",
            Token::Usdt => "USDT",
        }
    }

    pub fn parse(text: &str) -> Result<Token, VaultError> {
        match text.to_ascii_uppercase().as_str() {
            "USDC" => Ok(Token::Usdc),
            "USDT" => Ok(Token::Usdt),
            _ => Err(VaultError::BadRequest("token is USDC or USDT".into())),
        }
    }
}

/// A token's contract (or Solana mint) on a chain, in the chain's own form, and its decimals
/// (chain_pay's `ChainPay.Assets`).
pub struct Asset {
    pub contract: &'static str,
    pub decimals: u32,
}

pub fn asset(chain: Chain, token: Token) -> Option<Asset> {
    let contract = match (chain, token) {
        (Chain::Ethereum, Token::Usdc) => "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        (Chain::Ethereum, Token::Usdt) => "0xdac17f958d2ee523a2206206994597c13d831ec7",
        (Chain::Sepolia, Token::Usdc) => "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238",
        (Chain::Solana, Token::Usdc) => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        (Chain::Solana, Token::Usdt) => "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        (Chain::SolanaDevnet, Token::Usdc) => "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        (Chain::Tron, Token::Usdt) => "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        (Chain::TronNile, Token::Usdt) => "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
        // Tether publishes no Sepolia or Solana devnet USDT; Circle's USDC on Tron is retired.
        _ => return None,
    };
    Some(Asset { contract, decimals: 6 })
}

/// A wallet's caps. Only `vault wallet create` and `vault wallet caps` set them, with the
/// recovery key; nothing a caller sends changes them. The fee caps are each chain's own; a
/// wallet's caps for another chain are zero and left out of JSON.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// The most one payment may move, in millionths of a dollar.
    pub per_payment_micros: u64,
    /// The most the payments of a rolling 24 hours may move, in millionths of a dollar.
    pub daily_micros: u64,
    /// Ethereum: the highest `max_fee_per_gas` any signed transaction may offer, in wei.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_fee_per_gas: u64,
    /// Ethereum: the most the fees of a rolling 24 hours could come to at their worst, in wei.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub daily_fees_wei: u64,
    /// Tron: the highest `fee_limit` a signed transaction may carry, in sun.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_fee_limit_sun: u64,
    /// Tron: the most the fees of a rolling 24 hours could come to at their worst, in sun.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub daily_fees_sun: u64,
    /// Solana: the highest compute-unit price (the priority fee) a signed transaction may offer,
    /// in micro-lamports per compute unit.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_compute_unit_price: u64,
    /// Solana: the most the fees (and recipients' token-account rent) of a rolling 24 hours could
    /// come to at their worst, in lamports.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub daily_fees_lamports: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl Caps {
    /// The daily fee cap of the chain's family, in its smallest unit.
    pub fn daily_fees(&self, family: Family) -> u64 {
        match family {
            Family::Evm => self.daily_fees_wei,
            Family::Solana => self.daily_fees_lamports,
            Family::Tron => self.daily_fees_sun,
        }
    }

    pub fn validate(&self, chain: Chain) -> Result<(), VaultError> {
        let bad = |why: &str| VaultError::InvalidSecret(why.into());
        if self.per_payment_micros > self.daily_micros {
            return Err(bad("the per-payment cap is more than the daily cap"));
        }
        if self.daily_micros > MAX_DAILY_MICROS {
            return Err(bad("the daily cap is at most $1,000,000"));
        }
        let family = chain.family();
        let others = match family {
            Family::Evm => [self.max_fee_limit_sun, self.daily_fees_sun, self.max_compute_unit_price, self.daily_fees_lamports],
            Family::Solana => [self.max_fee_per_gas, self.daily_fees_wei, self.max_fee_limit_sun, self.daily_fees_sun],
            Family::Tron => [self.max_fee_per_gas, self.daily_fees_wei, self.max_compute_unit_price, self.daily_fees_lamports],
        };
        if others.iter().any(|cap| *cap != 0) {
            return Err(bad(&format!("a {} wallet's fee caps are in {}, not another chain's", chain.label(), family.coin())));
        }
        match family {
            Family::Evm if self.max_fee_per_gas > MAX_FEE_PER_GAS_CAP => Err(bad("the fee cap is at most 10,000 gwei per gas")),
            Family::Evm if self.daily_fees_wei > MAX_DAILY_FEES => Err(bad("the daily fee cap is at most 1 ETH")),
            Family::Tron if self.max_fee_limit_sun > MAX_FEE_LIMIT_CAP => Err(bad("the fee_limit cap is at most 1,000 TRX")),
            Family::Tron if self.daily_fees_sun > MAX_DAILY_FEES_SUN => Err(bad("the daily fee cap is at most 10,000 TRX")),
            Family::Solana if self.max_compute_unit_price > MAX_COMPUTE_UNIT_PRICE_CAP => {
                Err(bad("the priority fee cap is at most 50,000,000 micro-lamports per compute unit"))
            }
            Family::Solana if self.daily_fees_lamports > MAX_DAILY_FEES_LAMPORTS => Err(bad("the daily fee cap is at most 1 SOL")),
            _ => Ok(()),
        }
    }

    /// How the audit log and the command line show them.
    pub fn describe(&self, chain: Chain) -> String {
        let family = chain.family();
        let fee = match family {
            Family::Evm => format!("fees at most {} gwei/gas", decimal(self.max_fee_per_gas as u128, 9)),
            Family::Tron => format!("fee_limit at most {} TRX", decimal(self.max_fee_limit_sun as u128, 6)),
            Family::Solana => format!("priority fee at most {} micro-lamports/compute unit", self.max_compute_unit_price),
        };
        format!(
            "${}/payment, ${}/day, {fee} and {}/day",
            decimal(self.per_payment_micros as u128, 6),
            decimal(self.daily_micros as u128, 6),
            family.fee_text(self.daily_fees(family))
        )
    }
}

/// One signed payment, kept for a day for the daily caps and to spot a replacement.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    /// When it was signed, Unix seconds.
    pub at: u64,
    /// Ethereum: its nonce. Zero on Solana and Tron, which have none.
    #[serde(default)]
    pub nonce: u64,
    pub token: Token,
    /// The recipient, canonical.
    pub to: String,
    /// The token's own units.
    pub units: u128,
    /// What it counted against `daily_micros`.
    pub micros: u64,
    /// Its worst-case fee in the chain's smallest unit (wei, lamports, sun), as counted against
    /// the daily fee cap.
    #[serde(alias = "fee_wei")]
    pub fee: u64,
    /// Solana and Tron: what identifies the exact transaction (`Payment::identity`), so the very
    /// same one asked for again counts once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// What the vault keeps about a wallet besides its key (the record's value).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WalletInfo {
    pub chain: Chain,
    /// The address the key controls, canonical: lower-case `0x` hex on Ethereum, base58 on
    /// Solana, base58check `T...` on Tron.
    pub address: String,
    pub caps: Caps,
    /// The last day's payments, oldest first.
    #[serde(default)]
    pub spends: Vec<Spend>,
}

impl WalletInfo {
    fn in_window(&self, now: u64) -> impl Iterator<Item = &Spend> {
        self.spends.iter().filter(move |spend| spend.at.saturating_add(DAY_SECS) > now)
    }

    /// What the last day's payments came to: dollars (millionths) and worst-case fees (the chain's
    /// smallest unit).
    pub fn spent(&self, now: u64) -> (u64, u64) {
        self.in_window(now).fold((0u64, 0u64), |(micros, fees), spend| {
            (micros.saturating_add(spend.micros), fees.saturating_add(spend.fee))
        })
    }

    /// The address as a person should see it: EIP-55 mixed case on Ethereum, as stored elsewhere.
    pub fn display_address(&self) -> String {
        match self.chain.family() {
            Family::Evm => evm::parse_address(&self.address).map(|bytes| evm::checksummed(&bytes)).unwrap_or_else(|_| self.address.clone()),
            _ => self.address.clone(),
        }
    }
}

/// A new wallet's key and the address it controls, canonical, for a chain.
pub fn new_key(chain: Chain) -> Result<(SecretValue, String), VaultError> {
    match chain.family() {
        Family::Evm => {
            let key = evm::new_key()?;
            let address = evm::address_text(&evm::address_of_key(&key)?);
            Ok((key, address))
        }
        Family::Tron => {
            let key = evm::new_key()?;
            let address = tron::address_text(&evm::address_of_key(&key)?);
            Ok((key, address))
        }
        Family::Solana => {
            let key = solana::new_key()?;
            let address = solana::address_text(&solana::address_of_key(&key)?);
            Ok((key, address))
        }
    }
}

/// A `sign` request's transfer, as the caller gave it. Which of the chain fields it needs depends
/// on the wallet's chain; a field of another chain is refused.
#[derive(Default)]
pub struct SignArgs<'a> {
    pub chain: &'a str,
    pub token: &'a str,
    pub to: &'a str,
    /// A decimal in the token's own unit, e.g. "12.50".
    pub amount: &'a str,
    /// Who the payment is for (an agent, a run, a work item), for the audit log only.
    pub on_behalf_of: Option<&'a str>,
    // Ethereum.
    pub nonce: Option<u64>,
    pub gas_limit: Option<u64>,
    pub max_fee_per_gas: Option<u64>,
    pub max_priority_fee_per_gas: Option<u64>,
    /// How many replacement rungs to sign, 0 to `MAX_LADDER`.
    pub ladder: Option<usize>,
    /// A lower ceiling than the wallet's for the ladder's top fee, if the caller wants one.
    pub ladder_max_fee_per_gas: Option<u64>,
    // Solana.
    /// The recent blockhash (base58) the transaction is valid with.
    pub recent_blockhash: Option<&'a str>,
    pub compute_unit_limit: Option<u32>,
    /// Micro-lamports per compute unit (the priority fee); 0 when left out.
    pub compute_unit_price: Option<u64>,
    /// Whether to create the recipient's token account if it is missing; yes when left out.
    pub create_recipient_account: Option<bool>,
    // Tron.
    /// The ref block's number and id (TronGrid's `getnowblock`: `block_header.raw_data.number`
    /// and `blockID`).
    pub ref_block_num: Option<u64>,
    pub ref_block_id: Option<&'a str>,
    /// Unix milliseconds: when the transaction is made and when it stops being valid.
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
    /// The most TRX, in sun, the transfer may burn for energy.
    pub fee_limit: Option<u64>,
}

/// One Ethereum transaction's fees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fees {
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
}

/// Ethereum: the transfer at a nonce, its first fees and its ladder.
pub struct EvmPlan {
    pub contract: [u8; 20],
    pub to: [u8; 20],
    /// The token's own units.
    pub units: u128,
    pub nonce: u64,
    pub gas_limit: u64,
    pub first: Fees,
    /// The rungs after the first transaction, in rising order.
    pub ladder: Vec<Fees>,
}

/// What the vault will build and sign, per chain.
pub enum Plan {
    Evm(EvmPlan),
    Solana(solana::Transfer),
    Tron(tron::Transfer),
}

/// A checked transfer.
pub struct Payment {
    pub chain: Chain,
    pub token: Token,
    /// The token's contract or mint, as the chain writes it.
    pub contract_text: String,
    /// The recipient, canonical.
    pub to_text: String,
    pub units: u128,
    pub decimals: u32,
    pub micros: u64,
    pub plan: Plan,
    pub on_behalf_of: Option<String>,
}

impl Payment {
    /// Ethereum: the highest fees any of its transactions offers.
    pub fn top(&self) -> Option<Fees> {
        match &self.plan {
            Plan::Evm(plan) => Some(*plan.ladder.last().unwrap_or(&plan.first)),
            _ => None,
        }
    }

    /// Its worst-case fee in the chain's smallest unit: on Ethereum the gas limit at the top
    /// rung's fee; on Tron `fee_limit` and the bandwidth; on Solana the signature, the priority
    /// fee and the rent of a recipient's token account it may create.
    pub fn worst_fee(&self) -> u64 {
        match &self.plan {
            Plan::Evm(plan) => {
                let top = plan.ladder.last().unwrap_or(&plan.first);
                u64::try_from(plan.gas_limit as u128 * top.max_fee_per_gas as u128).unwrap_or(u64::MAX)
            }
            Plan::Solana(transfer) => transfer.worst_fee_lamports(),
            Plan::Tron(transfer) => transfer.worst_fee_sun(),
        }
    }

    /// Ethereum: its nonce.
    pub fn nonce(&self) -> Option<u64> {
        match &self.plan {
            Plan::Evm(plan) => Some(plan.nonce),
            _ => None,
        }
    }

    /// Solana and Tron: what identifies the exact transaction before it is signed. Tron's txid
    /// (sha256 of raw_data); on Solana sha256 of the message. Signing is deterministic on both, so
    /// the same identity is the same signed bytes.
    pub fn identity(&self) -> Result<Option<String>, VaultError> {
        Ok(match &self.plan {
            Plan::Evm(_) => None,
            Plan::Solana(transfer) => Some(format!("message {}", hex::encode(Sha256::digest(transfer.message()?)))),
            Plan::Tron(transfer) => Some(format!("txid {}", hex::encode(Sha256::digest(transfer.raw_data())))),
        })
    }

    pub fn amount_text(&self) -> String {
        decimal(self.units, self.decimals)
    }

    /// Ethereum: the transaction at one rung's fees.
    pub fn evm_tx(plan: &EvmPlan, chain: Chain, fees: Fees) -> evm::Tx {
        evm::Tx {
            chain_id: chain.chain_id().unwrap_or(0),
            nonce: plan.nonce,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit: plan.gas_limit,
            to: plan.contract,
            data: evm::transfer_data(&plan.to, plan.units),
        }
    }

    /// How the audit log describes it: chain, token, amount, recipient, the chain's own terms
    /// (nonce and fees; blockhash and priority fee; ref block, expiry and fee_limit), and who it
    /// is for. Never a key.
    pub fn describe(&self) -> String {
        let terms = match &self.plan {
            Plan::Evm(plan) => format!(
                "at nonce {}, gas {}, max fee {} gwei/gas (tip {})",
                plan.nonce,
                plan.gas_limit,
                decimal(plan.first.max_fee_per_gas as u128, 9),
                decimal(plan.first.max_priority_fee_per_gas as u128, 9)
            ),
            Plan::Solana(transfer) => format!(
                "with blockhash {}, {} compute units at {} micro-lamports{}",
                solana::address_text(&transfer.recent_blockhash),
                transfer.compute_unit_limit,
                transfer.compute_unit_price,
                if transfer.create_recipient_account { ", creating the recipient's token account if missing" } else { "" }
            ),
            Plan::Tron(transfer) => format!(
                "with ref block {}{}, valid {} to {} (ms), fee_limit {} TRX",
                hex::encode(transfer.ref_block_bytes),
                hex::encode(transfer.ref_block_hash),
                transfer.timestamp,
                transfer.expiration,
                decimal(transfer.fee_limit as u128, 6)
            ),
        };
        format!(
            "{} {} {} to {} {terms}{}",
            self.chain.label(),
            self.amount_text(),
            self.token.label(),
            self.to_text,
            self.on_behalf_of.as_ref().map(|who| format!(", for {who}")).unwrap_or_default()
        )
    }
}

fn bad(why: &str) -> VaultError {
    VaultError::BadRequest(why.into())
}

/// Reads a decimal amount ("12", "12.5", "0.000001") into a whole number of `decimals`-place
/// units. No sign, no exponent, no more places than the token has.
pub fn parse_amount(text: &str, decimals: u32) -> Result<u128, VaultError> {
    let invalid = || bad(&format!("amount is a decimal number with at most {decimals} places, like \"12.50\""));
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() || whole.len() > 24 || fraction.len() > decimals as usize {
        return Err(invalid());
    }
    if !whole.bytes().chain(fraction.bytes()).all(|b| b.is_ascii_digit()) || (text.contains('.') && fraction.is_empty()) {
        return Err(invalid());
    }
    let scale = 10u128.pow(decimals);
    let whole: u128 = whole.parse().map_err(|_| invalid())?;
    let mut padded = fraction.to_string();
    while padded.len() < decimals as usize {
        padded.push('0');
    }
    let fraction: u128 = if padded.is_empty() { 0 } else { padded.parse().map_err(|_| invalid())? };
    whole.checked_mul(scale).and_then(|units| units.checked_add(fraction)).ok_or_else(invalid)
}

/// A whole number of `decimals`-place units as a decimal, trailing zeros dropped.
pub fn decimal(units: u128, decimals: u32) -> String {
    let scale = 10u128.pow(decimals);
    let whole = units / scale;
    let fraction = units % scale;
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:0width$}", width = decimals as usize);
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

/// A token amount in millionths of a dollar, rounded up (a token with more than 6 decimals).
fn to_micros(units: u128, decimals: u32) -> Option<u64> {
    let micros = if decimals >= 6 {
        let div = 10u128.pow(decimals - 6);
        units.div_ceil(div)
    } else {
        units.checked_mul(10u128.pow(6 - decimals))?
    };
    u64::try_from(micros).ok()
}

/// The least a node takes to replace a transaction: 12.5% more, rounded up, and at least 1 wei
/// more (v1's `raise_fee`).
pub fn raise(fee: u64) -> u64 {
    let raised = (fee as u128 * 9).div_ceil(8);
    u64::try_from(raised).unwrap_or(u64::MAX).max(fee.saturating_add(1))
}

/// The ladder above `first`: up to `steps` rungs, each `raise`d from the one before, none
/// above `ceiling`. Stops at the first rung that would pass it.
pub fn ladder(first: Fees, steps: usize, ceiling: u64) -> Vec<Fees> {
    let mut rungs = Vec::with_capacity(steps.min(MAX_LADDER));
    let mut last = first;
    for _ in 0..steps.min(MAX_LADDER) {
        let next = Fees {
            max_fee_per_gas: raise(last.max_fee_per_gas),
            max_priority_fee_per_gas: raise(last.max_priority_fee_per_gas),
        };
        if next.max_fee_per_gas > ceiling {
            break;
        }
        rungs.push(next);
        last = next;
    }
    rungs
}

/// A caller's `on_behalf_of`: printable, at most 128 characters.
pub fn check_label(label: &str) -> Result<String, VaultError> {
    let ok = !label.trim().is_empty()
        && label.chars().count() <= MAX_LABEL_CHARS
        && label.chars().all(|c| !c.is_control() && c != '\u{7f}');
    if ok { Ok(label.to_string()) } else { Err(bad("on_behalf_of is 1 to 128 printable characters")) }
}

/// Refuses the fields that belong to other chains, so a request can't carry terms the vault would
/// silently ignore.
fn only_fields(chain: Chain, args: &SignArgs<'_>) -> Result<(), VaultError> {
    let evm = [
        ("nonce", args.nonce.is_some()),
        ("gas_limit", args.gas_limit.is_some()),
        ("max_fee_per_gas", args.max_fee_per_gas.is_some()),
        ("max_priority_fee_per_gas", args.max_priority_fee_per_gas.is_some()),
        ("ladder", args.ladder.is_some_and(|steps| steps > 0)),
        ("ladder_max_fee_per_gas", args.ladder_max_fee_per_gas.is_some()),
    ];
    let solana = [
        ("recent_blockhash", args.recent_blockhash.is_some()),
        ("compute_unit_limit", args.compute_unit_limit.is_some()),
        ("compute_unit_price", args.compute_unit_price.is_some()),
        ("create_recipient_account", args.create_recipient_account.is_some()),
    ];
    let tron = [
        ("ref_block_num", args.ref_block_num.is_some()),
        ("ref_block_id", args.ref_block_id.is_some()),
        ("timestamp", args.timestamp.is_some()),
        ("expiration", args.expiration.is_some()),
        ("fee_limit", args.fee_limit.is_some()),
    ];
    let foreign: Vec<&str> = match chain.family() {
        Family::Evm => solana.iter().chain(tron.iter()).filter(|(_, set)| *set).map(|(name, _)| *name).collect(),
        Family::Solana => evm.iter().chain(tron.iter()).filter(|(_, set)| *set).map(|(name, _)| *name).collect(),
        Family::Tron => evm.iter().chain(solana.iter()).filter(|(_, set)| *set).map(|(name, _)| *name).collect(),
    };
    if foreign.is_empty() {
        return Ok(());
    }
    let why = match chain.family() {
        Family::Evm => String::new(),
        Family::Solana => " (Solana has no nonce, and no ladder: see the README's \"Fee bumps\")".to_string(),
        Family::Tron => " (Tron has no nonce, and no ladder: see the README's \"Fee bumps\")".to_string(),
    };
    Err(bad(&format!("{} isn't a field of a {} payment{why}", foreign.join(", "), chain.label())))
}

fn required<T>(value: Option<T>, name: &str, chain: Chain) -> Result<T, VaultError> {
    value.ok_or_else(|| bad(&format!("{name} is needed for a {} payment", chain.label())))
}

/// Checks a `sign` request's fields against the wallet and builds the payment: the chain must be
/// the wallet's, the token one the chain has, the recipient a real address (not zero, not the
/// token's contract, not the wallet itself on Solana), the amount above zero, and the chain's own
/// terms within bounds and within the wallet's per-transaction fee cap. `now_ms` is the vault's
/// clock, which bounds a Tron transaction's life. Caps on amounts and daily fees are `decide`'s.
pub fn check(info: &WalletInfo, args: &SignArgs<'_>, now_ms: u64) -> Result<Payment, VaultError> {
    let chain = Chain::parse(args.chain)?;
    if chain != info.chain {
        return Err(bad(&format!("this wallet is for {}, not {}", info.chain.label(), chain.label())));
    }
    only_fields(chain, args)?;
    let token = Token::parse(args.token)?;
    let asset = asset(chain, token).ok_or_else(|| bad(&format!("{} isn't supported on {}", token.label(), chain.label())))?;
    let units = parse_amount(args.amount.trim(), asset.decimals)?;
    if units == 0 {
        return Err(bad("amount is more than zero"));
    }
    let micros = to_micros(units, asset.decimals).ok_or_else(|| VaultError::OverCap("the amount is too large".into()))?;
    let on_behalf_of = args.on_behalf_of.map(check_label).transpose()?;
    let to_given = args.to.trim();
    let (plan, to_text) = match chain.family() {
        Family::Evm => {
            let contract = evm::parse_address(asset.contract)?;
            let to = evm::parse_address(to_given)?;
            if to == [0u8; 20] {
                return Err(bad("the recipient is the zero address, which burns what it receives"));
            }
            if to == contract {
                return Err(bad("the recipient is the token's own contract, which can't give it back"));
            }
            let gas_limit = required(args.gas_limit, "gas_limit", chain)?;
            if !(MIN_GAS_LIMIT..=MAX_GAS_LIMIT).contains(&gas_limit) {
                return Err(bad(&format!("gas_limit is {MIN_GAS_LIMIT} to {MAX_GAS_LIMIT} for a token transfer")));
            }
            let first = Fees {
                max_fee_per_gas: required(args.max_fee_per_gas, "max_fee_per_gas", chain)?,
                max_priority_fee_per_gas: required(args.max_priority_fee_per_gas, "max_priority_fee_per_gas", chain)?,
            };
            if first.max_fee_per_gas == 0 || first.max_priority_fee_per_gas > first.max_fee_per_gas {
                return Err(bad("max_fee_per_gas is above zero and at least max_priority_fee_per_gas"));
            }
            if first.max_fee_per_gas > info.caps.max_fee_per_gas {
                return Err(VaultError::OverCap(format!(
                    "max_fee_per_gas {} gwei is over this wallet's fee cap of {} gwei",
                    decimal(first.max_fee_per_gas as u128, 9),
                    decimal(info.caps.max_fee_per_gas as u128, 9)
                )));
            }
            let steps = args.ladder.unwrap_or(0);
            if steps > MAX_LADDER {
                return Err(bad(&format!("ladder is 0 to {MAX_LADDER} rungs")));
            }
            let ceiling = args.ladder_max_fee_per_gas.map_or(info.caps.max_fee_per_gas, |own| own.min(info.caps.max_fee_per_gas));
            let plan = EvmPlan {
                contract,
                to,
                nonce: required(args.nonce, "nonce", chain)?,
                gas_limit,
                first,
                ladder: ladder(first, steps, ceiling),
                units,
            };
            (Plan::Evm(plan), evm::address_text(&to))
        }
        Family::Solana => {
            let owner = solana::parse_address(&info.address).map_err(|_| VaultError::VaultFileCorrupt)?;
            let mint = solana::parse_address(asset.contract)?;
            let to = solana::parse_address(to_given)?;
            if to == owner {
                return Err(bad("the recipient is this wallet itself"));
            }
            if to == mint || to == [0u8; 32] {
                return Err(bad("the recipient is the token's mint or the system program, which can't give it back"));
            }
            let compute_unit_limit = required(args.compute_unit_limit, "compute_unit_limit", chain)?;
            if !(solana::MIN_COMPUTE_UNITS..=solana::MAX_COMPUTE_UNITS).contains(&compute_unit_limit) {
                return Err(bad(&format!(
                    "compute_unit_limit is {} to {} for a token transfer",
                    solana::MIN_COMPUTE_UNITS,
                    solana::MAX_COMPUTE_UNITS
                )));
            }
            let compute_unit_price = args.compute_unit_price.unwrap_or(0);
            if compute_unit_price > info.caps.max_compute_unit_price {
                return Err(VaultError::OverCap(format!(
                    "compute_unit_price {compute_unit_price} micro-lamports is over this wallet's priority fee cap of {} micro-lamports per compute unit",
                    info.caps.max_compute_unit_price
                )));
            }
            let transfer = solana::Transfer {
                owner,
                to,
                mint,
                decimals: asset.decimals as u8,
                units: u64::try_from(units).map_err(|_| VaultError::OverCap("the amount is too large".into()))?,
                recent_blockhash: solana::parse_blockhash(required(args.recent_blockhash, "recent_blockhash", chain)?)?,
                compute_unit_limit,
                compute_unit_price,
                create_recipient_account: args.create_recipient_account.unwrap_or(true),
            };
            // Builds the message once here, so a recipient that collides with an account the
            // transaction already names is refused before anything counts.
            transfer.message()?;
            (Plan::Solana(transfer), solana::address_text(&to))
        }
        Family::Tron => {
            let owner = tron::parse_address(&info.address).map_err(|_| VaultError::VaultFileCorrupt)?;
            let contract = tron::parse_address(asset.contract)?;
            let to = tron::parse_address(to_given)?;
            if to == [0u8; 20] {
                return Err(bad("the recipient is the zero address, which burns what it receives"));
            }
            if to == contract {
                return Err(bad("the recipient is the token's own contract, which can't give it back"));
            }
            if to == owner {
                return Err(bad("the recipient is this wallet itself"));
            }
            let number = required(args.ref_block_num, "ref_block_num", chain)?;
            let block_id = tron::parse_block_id(required(args.ref_block_id, "ref_block_id", chain)?, number)?;
            let (ref_block_bytes, ref_block_hash) = tron::ref_block(number, &block_id);
            let timestamp = required(args.timestamp, "timestamp", chain)?;
            let expiration = required(args.expiration, "expiration", chain)?;
            if expiration <= timestamp || expiration - timestamp > tron::MAX_LIFE_MS {
                return Err(bad("expiration is after timestamp, by at most 60,000 ms"));
            }
            if expiration <= now_ms {
                return Err(bad("expiration has already passed by the vault's clock"));
            }
            if expiration > now_ms.saturating_add(tron::MAX_LIFE_MS + tron::CLOCK_SKEW_MS) {
                return Err(bad("expiration is at most 60 seconds from now by the vault's clock (90 with its allowance for skew)"));
            }
            let fee_limit = required(args.fee_limit, "fee_limit", chain)?;
            if fee_limit == 0 {
                return Err(bad("fee_limit is above zero"));
            }
            if fee_limit > info.caps.max_fee_limit_sun {
                return Err(VaultError::OverCap(format!(
                    "fee_limit {} TRX is over this wallet's fee_limit cap of {} TRX",
                    decimal(fee_limit as u128, 6),
                    decimal(info.caps.max_fee_limit_sun as u128, 6)
                )));
            }
            let transfer = tron::Transfer {
                owner,
                contract,
                to,
                units,
                ref_block_bytes,
                ref_block_hash,
                timestamp,
                expiration,
                fee_limit,
            };
            (Plan::Tron(transfer), tron::address_text(&to))
        }
    };
    Ok(Payment {
        chain,
        token,
        contract_text: asset.contract.to_string(),
        to_text,
        units,
        decimals: asset.decimals,
        micros,
        plan,
        on_behalf_of,
    })
}

/// What a payment counts against the daily caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counted {
    pub micros: u64,
    /// In the chain's smallest unit.
    pub fee: u64,
    /// The index of the spend it replaces: on Ethereum the same transfer at the same nonce, on
    /// Solana and Tron the very same transaction, in the last day.
    pub replaces: Option<usize>,
}

/// Whether the caps allow a payment now, and what it counts: refused (`over_cap`) when it would
/// pass the per-payment cap, the daily cap or the daily fee cap.
pub fn decide(info: &WalletInfo, payment: &Payment, now: u64) -> Result<Counted, VaultError> {
    let caps = info.caps;
    let family = info.chain.family();
    if payment.micros > caps.per_payment_micros {
        return Err(VaultError::OverCap(format!(
            "${} is over this wallet's per-payment cap of ${}",
            decimal(payment.micros as u128, 6),
            decimal(caps.per_payment_micros as u128, 6)
        )));
    }
    let to_text = &payment.to_text;
    let identity = payment.identity()?;
    let replaces = info.spends.iter().position(|spend| {
        let same = match (&identity, payment.nonce()) {
            (Some(identity), _) => spend.identity.as_ref() == Some(identity),
            (None, Some(nonce)) => spend.identity.is_none() && spend.nonce == nonce,
            (None, None) => false,
        };
        spend.at.saturating_add(DAY_SECS) > now && same && spend.token == payment.token && &spend.to == to_text && spend.units == payment.units
    });
    let worst = payment.worst_fee();
    let counted = match replaces {
        Some(index) => Counted { micros: 0, fee: worst.saturating_sub(info.spends[index].fee), replaces },
        None => Counted { micros: payment.micros, fee: worst, replaces: None },
    };
    let (spent, fees) = info.spent(now);
    if spent.saturating_add(counted.micros) > caps.daily_micros {
        return Err(VaultError::OverCap(format!(
            "${} would bring the last 24 hours to ${}, over this wallet's daily cap of ${}",
            decimal(payment.micros as u128, 6),
            decimal(spent.saturating_add(counted.micros) as u128, 6),
            decimal(caps.daily_micros as u128, 6)
        )));
    }
    let daily_fees = caps.daily_fees(family);
    if fees.saturating_add(counted.fee) > daily_fees {
        return Err(VaultError::OverCap(format!(
            "its fees could reach {}, bringing the last 24 hours to {}, over this wallet's daily fee cap of {}",
            family.fee_text(worst),
            family.fee_text(fees.saturating_add(counted.fee)),
            family.fee_text(daily_fees)
        )));
    }
    if replaces.is_none() && info.in_window(now).count() >= MAX_SPENDS {
        return Err(VaultError::OverCap(format!("{MAX_SPENDS} payments in the last 24 hours is the most a wallet signs")));
    }
    Ok(counted)
}

/// Records a payment `decide` allowed: drops spends older than a day, then adds this one, or
/// raises the replaced one's fee to this worst case.
pub fn record(info: &mut WalletInfo, payment: &Payment, counted: Counted, now: u64) -> Result<(), VaultError> {
    let worst = payment.worst_fee();
    if let Some(index) = counted.replaces {
        let spend = &mut info.spends[index];
        spend.fee = spend.fee.max(worst);
    } else {
        info.spends.push(Spend {
            at: now,
            nonce: payment.nonce().unwrap_or(0),
            token: payment.token,
            to: payment.to_text.clone(),
            units: payment.units,
            micros: payment.micros,
            fee: worst,
            identity: payment.identity()?,
        });
    }
    info.spends.retain(|spend| spend.at.saturating_add(DAY_SECS) > now);
    Ok(())
}

/// One signed transaction as the relay sends it: its bytes in the chain's broadcast form and its
/// id as the chain's explorers show it.
#[derive(Clone, Debug)]
pub struct SignedTx {
    /// Ethereum: `0x` hex for `eth_sendRawTransaction`. Solana: base64 for `sendTransaction`.
    /// Tron: hex of the whole `Transaction` for `/wallet/broadcasthex`.
    pub raw: String,
    /// Ethereum: the `0x` hash. Solana: the base58 signature. Tron: the txid in hex.
    pub hash: String,
    /// Ethereum: this transaction's fees.
    pub fees: Option<Fees>,
    /// Tron: raw_data in hex, for `/wallet/broadcasttransaction`'s JSON form.
    pub raw_data_hex: Option<String>,
}

/// A payment signed: the first transaction and, on Ethereum, its ladder.
pub struct Signatures {
    pub first: SignedTx,
    pub ladder: Vec<SignedTx>,
}

/// Signs a payment `check` built and `decide` allowed, with the wallet's key. Each signature is
/// checked against the wallet's address before it leaves (`evm::sign_digest`, `solana::sign`).
pub fn sign(info: &WalletInfo, payment: &Payment, key: &SecretValue) -> Result<Signatures, VaultError> {
    match &payment.plan {
        Plan::Evm(plan) => {
            let from = evm::parse_address(&info.address).map_err(|_| VaultError::VaultFileCorrupt)?;
            let one = |fees: Fees| -> Result<SignedTx, VaultError> {
                let signed = evm::sign(&Payment::evm_tx(plan, payment.chain, fees), key, &from)?;
                Ok(SignedTx {
                    raw: format!("0x{}", hex::encode(&signed.raw)),
                    hash: format!("0x{}", hex::encode(signed.hash)),
                    fees: Some(fees),
                    raw_data_hex: None,
                })
            };
            let first = one(plan.first)?;
            let ladder = plan.ladder.iter().map(|fees| one(*fees)).collect::<Result<Vec<_>, _>>()?;
            Ok(Signatures { first, ladder })
        }
        Plan::Solana(transfer) => {
            use base64::Engine as _;
            let signed = solana::sign(transfer, key)?;
            Ok(Signatures {
                first: SignedTx {
                    raw: base64::engine::general_purpose::STANDARD.encode(&signed.raw),
                    hash: bs58::encode(signed.signature).into_string(),
                    fees: None,
                    raw_data_hex: None,
                },
                ladder: Vec::new(),
            })
        }
        Plan::Tron(transfer) => {
            let signed = tron::sign(transfer, key)?;
            Ok(Signatures {
                first: SignedTx {
                    raw: hex::encode(&signed.raw),
                    hash: hex::encode(signed.txid),
                    fees: None,
                    raw_data_hex: Some(hex::encode(&signed.raw_data)),
                },
                ladder: Vec::new(),
            })
        }
    }
}

/// A `sign` request's cancel (#7491), as the caller gave it: no recipient, token or amount, since
/// the vault builds the one transaction a cancel can be.
pub struct CancelArgs<'a> {
    pub chain: &'a str,
    /// Payment fields the caller sent anyway (`to`, `token`, `amount`): any refuses the cancel.
    pub extra: Vec<&'static str>,
    /// Refused unless absent or 21,000.
    pub gas_limit: Option<u64>,
    pub nonce: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    /// How many replacement rungs to sign, 0 to `MAX_LADDER`.
    pub ladder: usize,
    pub ladder_max_fee_per_gas: Option<u64>,
    pub on_behalf_of: Option<&'a str>,
}

/// The gas a cancel is given: a plain transfer of ETH, which takes exactly 21,000.
pub const CANCEL_GAS: u64 = 21_000;

/// A checked cancel: a transfer of 0 ETH from the wallet to itself, with no data, at the nonce of
/// a payment it signed in the last day. Whichever of the two mines takes the nonce; if the cancel
/// does, nothing is paid (v1's `Wallets.Chains.replace(..., :cancel)`).
pub struct Cancel {
    pub chain: Chain,
    /// The wallet's own address: the cancel's sender and its recipient.
    pub address: [u8; 20],
    pub nonce: u64,
    pub first: Fees,
    /// The rungs after the first transaction, in rising order.
    pub ladder: Vec<Fees>,
    /// The payments it cancels: those signed at this nonce in the last day.
    pub cancels: Vec<String>,
    pub on_behalf_of: Option<String>,
}

impl Cancel {
    pub fn top(&self) -> Fees {
        *self.ladder.last().unwrap_or(&self.first)
    }

    /// Its worst-case fee in wei: 21,000 gas at the top rung's fee.
    pub fn worst_fee_wei(&self) -> u64 {
        u64::try_from(CANCEL_GAS as u128 * self.top().max_fee_per_gas as u128).unwrap_or(u64::MAX)
    }

    /// The transaction at one rung's fees: value 0, to itself, no data.
    pub fn tx(&self, fees: Fees) -> evm::Tx {
        evm::Tx {
            chain_id: self.chain.chain_id().unwrap_or(0),
            nonce: self.nonce,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit: CANCEL_GAS,
            to: self.address,
            data: Vec::new(),
        }
    }

    /// How the audit log describes it: the nonce, the fees, what it cancels and who it is for.
    pub fn describe(&self) -> String {
        format!(
            "{} cancel at nonce {} (0 ETH to itself, gas {}), max fee {} gwei/gas (tip {}); cancels {}{}",
            self.chain.label(),
            self.nonce,
            CANCEL_GAS,
            decimal(self.first.max_fee_per_gas as u128, 9),
            decimal(self.first.max_priority_fee_per_gas as u128, 9),
            self.cancels.join(" and "),
            self.on_behalf_of.as_ref().map(|who| format!(", for {who}")).unwrap_or_default()
        )
    }
}

/// Checks a cancel against the wallet: its chain, a nonce it signed a payment for in the last
/// day (a cancel anywhere else could only take a nonce the relay hasn't used yet, or one already
/// mined), and fees in order and within the fee cap, with the ladder cut at the ceiling exactly
/// as a payment's is. The daily fee cap is `decide_cancel`'s.
pub fn check_cancel(info: &WalletInfo, args: &CancelArgs<'_>, now: u64) -> Result<Cancel, VaultError> {
    let chain = Chain::parse(args.chain)?;
    if chain != info.chain {
        return Err(bad(&format!("this wallet is for {}, not {}", info.chain.label(), chain.label())));
    }
    // Only Ethereum has a nonce to cancel at (#7490): a Solana or Tron payment stops at its
    // blockhash or expiration instead.
    if chain.family() != Family::Evm {
        return Err(bad(&format!(
            "a cancel is for Ethereum wallets only: a {} payment has no nonce to cancel at, and stops by itself when its {}",
            chain.label(),
            if chain.family() == Family::Solana { "blockhash expires" } else { "expiration passes" }
        )));
    }
    if !args.extra.is_empty() {
        return Err(bad(&format!(
            "a cancel takes no {}: the vault builds it as 0 ETH from the wallet to itself",
            args.extra.join(" or ")
        )));
    }
    if args.gas_limit.is_some_and(|gas| gas != CANCEL_GAS) {
        return Err(bad(&format!("a cancel's gas_limit is {CANCEL_GAS}, a plain transfer of ETH")));
    }
    let address = evm::parse_address(&info.address).map_err(|_| VaultError::VaultFileCorrupt)?;
    let cancels: Vec<String> = info
        .in_window(now)
        .filter(|spend| spend.nonce == args.nonce)
        .map(|spend| {
            let decimals = asset(info.chain, spend.token).map_or(6, |asset| asset.decimals);
            format!("{} {} to {}", decimal(spend.units, decimals), spend.token.label(), spend.to)
        })
        .collect();
    if cancels.is_empty() {
        return Err(bad(&format!(
            "this wallet signed no payment at nonce {} in the last 24 hours, so there is nothing there to cancel",
            args.nonce
        )));
    }
    let first = Fees { max_fee_per_gas: args.max_fee_per_gas, max_priority_fee_per_gas: args.max_priority_fee_per_gas };
    if first.max_fee_per_gas == 0 || first.max_priority_fee_per_gas > first.max_fee_per_gas {
        return Err(bad("max_fee_per_gas is above zero and at least max_priority_fee_per_gas"));
    }
    if first.max_fee_per_gas > info.caps.max_fee_per_gas {
        return Err(VaultError::OverCap(format!(
            "max_fee_per_gas {} gwei is over this wallet's fee cap of {} gwei",
            decimal(first.max_fee_per_gas as u128, 9),
            decimal(info.caps.max_fee_per_gas as u128, 9)
        )));
    }
    if args.ladder > MAX_LADDER {
        return Err(bad(&format!("ladder is 0 to {MAX_LADDER} rungs")));
    }
    let ceiling = args.ladder_max_fee_per_gas.map_or(info.caps.max_fee_per_gas, |own| own.min(info.caps.max_fee_per_gas));
    let on_behalf_of = args.on_behalf_of.map(check_label).transpose()?;
    Ok(Cancel { chain, address, nonce: args.nonce, first, ladder: ladder(first, args.ladder, ceiling), cancels, on_behalf_of })
}

/// What a cancel counts against the daily fee cap: only one transaction per nonce can mine, so
/// it counts for what it raises that nonce's worst case by (the costliest spend there), the way a
/// replacement does. It moves no value and counts no amount. Refused (`over_cap`) when that would
/// pass the daily fee cap.
pub fn decide_cancel(info: &WalletInfo, cancel: &Cancel, now: u64) -> Result<Counted, VaultError> {
    let at_nonce = info
        .spends
        .iter()
        .enumerate()
        .filter(|(_, spend)| spend.at.saturating_add(DAY_SECS) > now && spend.identity.is_none() && spend.nonce == cancel.nonce)
        .max_by_key(|(_, spend)| spend.fee)
        .map(|(index, _)| index)
        .ok_or_else(|| bad(&format!("this wallet signed no payment at nonce {} in the last 24 hours", cancel.nonce)))?;
    let worst = cancel.worst_fee_wei();
    let counted = Counted { micros: 0, fee: worst.saturating_sub(info.spends[at_nonce].fee), replaces: Some(at_nonce) };
    let (_, fees) = info.spent(now);
    if fees.saturating_add(counted.fee) > info.caps.daily_fees_wei {
        return Err(VaultError::OverCap(format!(
            "its fees could reach {} ETH, bringing the last 24 hours to {} ETH, over this wallet's daily fee cap of {} ETH",
            decimal(worst as u128, 18),
            decimal(fees.saturating_add(counted.fee) as u128, 18),
            decimal(info.caps.daily_fees_wei as u128, 18)
        )));
    }
    Ok(counted)
}

/// Records a cancel `decide_cancel` allowed: the spend at its nonce now counts the cancel's worst
/// case if that is higher, and spends older than a day leave.
pub fn record_cancel(info: &mut WalletInfo, cancel: &Cancel, counted: Counted, now: u64) {
    if let Some(index) = counted.replaces {
        let spend = &mut info.spends[index];
        spend.fee = spend.fee.max(cancel.worst_fee_wei());
    }
    info.spends.retain(|spend| spend.at.saturating_add(DAY_SECS) > now);
}
