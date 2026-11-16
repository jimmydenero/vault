//! Wallets (#7440): a key the vault makes itself and never gives out, used only to sign a token
//! transfer it builds from structured fields, inside caps only the person on the vault's machine
//! sets. The decisions are pure functions here; `evm` encodes and signs; the daemon (`server`)
//! reads the request, records the spend and the audit lines, and answers.
//!
//! **Chains and tokens.** The EVM chains v1's agent wallets used (brennancheung/platform-ops
//! `Wallets.Chains`): Ethereum mainnet, with USDC and USDT, plus Sepolia (USDC) for a dry run on a
//! test network. Contracts and decimals are chain_pay's `ChainPay.Assets`. Solana and Tron, which
//! v1 also used, aren't here yet.
//!
//! **Caps** (`Caps`), set when the wallet is made and changed only with the recovery key, since
//! the socket can't tell the person from an agent (R23):
//! - `per_payment` and `daily` (rolling 24 hours), in US dollars: USDC and USDT count one for one;
//! - `max_fee_per_gas`: no transaction the vault signs, a ladder's top rung included, may offer
//!   more per unit of gas;
//! - `daily_fees`: the most the signed transactions of a rolling 24 hours could burn in fees,
//!   each payment counted at its worst case (`gas_limit` times its ladder's top fee).
//!
//! **The ladder** (`ladder`): the same transfer, at the same nonce, at rising fees, so the relay
//! can replace a payment that stalls while the vault is offline. Only one transaction per nonce
//! can mine, so a ladder can never pay twice. Each rung raises both fees by 12.5% (rounded up,
//! at least 1 wei), the least a node takes as a replacement (v1's `bump_fees`). At most
//! `MAX_LADDER` rungs, so its top is at most about 1.6 times the first fee; never above the
//! wallet's `max_fee_per_gas` or the caller's own `ladder_max_fee_per_gas`, whichever is lower (a
//! rung that would pass it isn't signed); and the worst case of the whole ladder counts against
//! `daily_fees` before anything is signed.
//!
//! **A replacement** (the same transfer at a nonce already signed for in the last day) counts
//! once against the amount caps, since only one of the two can mine; its fee counts only for
//! what it raises the worst case by.

use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::evm;

/// A day, in seconds: the window of the daily caps.
pub const DAY_SECS: u64 = 86_400;
/// The most rungs a ladder has.
pub const MAX_LADDER: usize = 4;
/// The gas a token transfer may be given: an ERC-20 `transfer` takes about 35,000 to 65,000.
pub const MIN_GAS_LIMIT: u64 = 21_000;
pub const MAX_GAS_LIMIT: u64 = 150_000;
/// Upper bounds on caps, against a typing slip: a million dollars a day, 10,000 gwei, 1 ETH.
pub const MAX_DAILY_MICROS: u64 = 1_000_000 * MICROS;
pub const MAX_FEE_PER_GAS_CAP: u64 = 10_000 * GWEI;
pub const MAX_DAILY_FEES: u64 = WEI_PER_ETH;
/// The most spends a wallet remembers (a day's worth): further signing is refused until older
/// ones leave the window, so the vault file can't grow without end.
pub const MAX_SPENDS: usize = 500;
/// The longest `on_behalf_of` a caller may give for the audit log.
pub const MAX_LABEL_CHARS: usize = 128;

/// Dollars are kept in millionths (USDC's and USDT's own unit on Ethereum).
pub const MICROS: u64 = 1_000_000;
pub const GWEI: u64 = 1_000_000_000;
pub const WEI_PER_ETH: u64 = 1_000_000_000_000_000_000;

/// The chains a wallet can be made for.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    /// Ethereum mainnet, chain id 1.
    Ethereum,
    /// Ethereum's Sepolia test network, chain id 11155111: test tokens with no value.
    Sepolia,
}

impl Chain {
    pub const ALL: [Chain; 2] = [Chain::Ethereum, Chain::Sepolia];

    pub fn label(self) -> &'static str {
        match self {
            Chain::Ethereum => "ethereum",
            Chain::Sepolia => "sepolia",
        }
    }

    pub fn chain_id(self) -> u64 {
        match self {
            Chain::Ethereum => 1,
            Chain::Sepolia => 11_155_111,
        }
    }

    pub fn parse(text: &str) -> Result<Chain, VaultError> {
        Chain::ALL
            .into_iter()
            .find(|chain| chain.label() == text)
            .ok_or_else(|| VaultError::BadRequest("chain is ethereum or sepolia (Solana and Tron aren't supported yet)".into()))
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

/// A token's contract on a chain and its decimals (chain_pay's `ChainPay.Assets`).
pub struct Asset {
    pub contract: &'static str,
    pub decimals: u32,
}

pub fn asset(chain: Chain, token: Token) -> Option<Asset> {
    match (chain, token) {
        (Chain::Ethereum, Token::Usdc) => Some(Asset { contract: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", decimals: 6 }),
        (Chain::Ethereum, Token::Usdt) => Some(Asset { contract: "0xdac17f958d2ee523a2206206994597c13d831ec7", decimals: 6 }),
        (Chain::Sepolia, Token::Usdc) => Some(Asset { contract: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238", decimals: 6 }),
        (Chain::Sepolia, Token::Usdt) => None,
    }
}

/// A wallet's caps. Only `vault wallet create` and `vault wallet caps` set them, with the
/// recovery key; nothing a caller sends changes them.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// The most one payment may move, in millionths of a dollar.
    pub per_payment_micros: u64,
    /// The most the payments of a rolling 24 hours may move, in millionths of a dollar.
    pub daily_micros: u64,
    /// The highest `max_fee_per_gas` any signed transaction may offer, in wei.
    pub max_fee_per_gas: u64,
    /// The most the fees of a rolling 24 hours could come to at their worst, in wei.
    pub daily_fees_wei: u64,
}

impl Caps {
    pub fn validate(&self) -> Result<(), VaultError> {
        let bad = |why: &str| VaultError::InvalidSecret(why.into());
        if self.per_payment_micros > self.daily_micros {
            return Err(bad("the per-payment cap is more than the daily cap"));
        }
        if self.daily_micros > MAX_DAILY_MICROS {
            return Err(bad("the daily cap is at most $1,000,000"));
        }
        if self.max_fee_per_gas > MAX_FEE_PER_GAS_CAP {
            return Err(bad("the fee cap is at most 10,000 gwei per gas"));
        }
        if self.daily_fees_wei > MAX_DAILY_FEES {
            return Err(bad("the daily fee cap is at most 1 ETH"));
        }
        Ok(())
    }

    /// How the audit log and the command line show them.
    pub fn describe(&self) -> String {
        format!(
            "${}/payment, ${}/day, fees at most {} gwei/gas and {} ETH/day",
            decimal(self.per_payment_micros as u128, 6),
            decimal(self.daily_micros as u128, 6),
            decimal(self.max_fee_per_gas as u128, 9),
            decimal(self.daily_fees_wei as u128, 18)
        )
    }
}

/// One signed payment, kept for a day for the daily caps and to spot a replacement.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    /// When it was signed, Unix seconds.
    pub at: u64,
    pub nonce: u64,
    pub token: Token,
    /// The recipient, canonical.
    pub to: String,
    /// The token's own units.
    pub units: u128,
    /// What it counted against `daily_micros`.
    pub micros: u64,
    /// Its worst-case fee in wei, as counted against `daily_fees_wei`.
    pub fee_wei: u64,
}

/// What the vault keeps about a wallet besides its key (the record's value).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WalletInfo {
    pub chain: Chain,
    /// The address the key controls, canonical (lower-case `0x` hex).
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

    /// What the last day's payments came to: dollars (millionths) and worst-case fees (wei).
    pub fn spent(&self, now: u64) -> (u64, u64) {
        self.in_window(now).fold((0u64, 0u64), |(micros, fees), spend| {
            (micros.saturating_add(spend.micros), fees.saturating_add(spend.fee_wei))
        })
    }
}

/// A `sign` request's transfer, as the caller gave it.
pub struct SignArgs<'a> {
    pub chain: &'a str,
    pub token: &'a str,
    pub to: &'a str,
    /// A decimal in the token's own unit, e.g. "12.50".
    pub amount: &'a str,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    /// How many replacement rungs to sign, 0 to `MAX_LADDER`.
    pub ladder: usize,
    /// A lower ceiling than the wallet's for the ladder's top fee, if the caller wants one.
    pub ladder_max_fee_per_gas: Option<u64>,
    /// Who the payment is for (an agent, a run, a work item), for the audit log only.
    pub on_behalf_of: Option<&'a str>,
}

/// One transaction's fees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fees {
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
}

/// A checked transfer: what the vault will build and sign.
pub struct Payment {
    pub chain: Chain,
    pub token: Token,
    pub contract: [u8; 20],
    pub to: [u8; 20],
    pub to_text: String,
    pub units: u128,
    pub decimals: u32,
    pub micros: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub first: Fees,
    /// The rungs after the first transaction, in rising order.
    pub ladder: Vec<Fees>,
    pub on_behalf_of: Option<String>,
}

impl Payment {
    /// The highest fee per gas any of its transactions offers.
    pub fn top(&self) -> Fees {
        *self.ladder.last().unwrap_or(&self.first)
    }

    /// Its worst-case fee in wei: the gas limit at the top rung's fee.
    pub fn worst_fee_wei(&self) -> u64 {
        let wei = self.gas_limit as u128 * self.top().max_fee_per_gas as u128;
        u64::try_from(wei).unwrap_or(u64::MAX)
    }

    pub fn amount_text(&self) -> String {
        decimal(self.units, self.decimals)
    }

    /// The transaction at one rung's fees.
    pub fn tx(&self, fees: Fees) -> evm::Tx {
        evm::Tx {
            chain_id: self.chain.chain_id(),
            nonce: self.nonce,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.contract,
            data: evm::transfer_data(&self.to, self.units),
        }
    }

    /// How the audit log describes it: chain, token, amount, recipient, nonce, fees, and who it
    /// is for. Never a key.
    pub fn describe(&self) -> String {
        format!(
            "{} {} {} to {} at nonce {}, gas {}, max fee {} gwei/gas (tip {}){}",
            self.chain.label(),
            self.amount_text(),
            self.token.label(),
            self.to_text,
            self.nonce,
            self.gas_limit,
            decimal(self.first.max_fee_per_gas as u128, 9),
            decimal(self.first.max_priority_fee_per_gas as u128, 9),
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

/// Checks a `sign` request's fields against the wallet and builds the payment: the chain must be
/// the wallet's, the token one the chain has, the recipient a real address (not zero, not the
/// token's contract), the amount above zero, the gas within bounds, the fees in order and within
/// the wallet's fee cap. The ladder is cut where it would pass the ceiling. Caps on amounts and
/// daily fees are `decide`'s.
pub fn check(info: &WalletInfo, args: &SignArgs<'_>) -> Result<Payment, VaultError> {
    let chain = Chain::parse(args.chain)?;
    if chain != info.chain {
        return Err(bad(&format!("this wallet is for {}, not {}", info.chain.label(), chain.label())));
    }
    let token = Token::parse(args.token)?;
    let asset = asset(chain, token)
        .ok_or_else(|| bad(&format!("{} isn't supported on {}", token.label(), chain.label())))?;
    let contract = evm::parse_address(asset.contract)?;
    let to = evm::parse_address(args.to.trim())?;
    if to == [0u8; 20] {
        return Err(bad("the recipient is the zero address, which burns what it receives"));
    }
    if to == contract {
        return Err(bad("the recipient is the token's own contract, which can't give it back"));
    }
    let units = parse_amount(args.amount.trim(), asset.decimals)?;
    if units == 0 {
        return Err(bad("amount is more than zero"));
    }
    let micros = to_micros(units, asset.decimals).ok_or_else(|| VaultError::OverCap("the amount is too large".into()))?;
    if !(MIN_GAS_LIMIT..=MAX_GAS_LIMIT).contains(&args.gas_limit) {
        return Err(bad(&format!("gas_limit is {MIN_GAS_LIMIT} to {MAX_GAS_LIMIT} for a token transfer")));
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
    Ok(Payment {
        chain,
        token,
        contract,
        to,
        to_text: evm::address_text(&to),
        units,
        decimals: asset.decimals,
        micros,
        nonce: args.nonce,
        gas_limit: args.gas_limit,
        first,
        ladder: ladder(first, args.ladder, ceiling),
        on_behalf_of,
    })
}

/// What a payment counts against the daily caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counted {
    pub micros: u64,
    pub fee_wei: u64,
    /// The index of the spend it replaces (the same transfer at the same nonce in the last day).
    pub replaces: Option<usize>,
}

/// Whether the caps allow a payment now, and what it counts: refused (`over_cap`) when it would
/// pass the per-payment cap, the daily cap or the daily fee cap.
pub fn decide(info: &WalletInfo, payment: &Payment, now: u64) -> Result<Counted, VaultError> {
    let caps = info.caps;
    if payment.micros > caps.per_payment_micros {
        return Err(VaultError::OverCap(format!(
            "${} is over this wallet's per-payment cap of ${}",
            decimal(payment.micros as u128, 6),
            decimal(caps.per_payment_micros as u128, 6)
        )));
    }
    let to_text = &payment.to_text;
    let replaces = info.spends.iter().position(|spend| {
        spend.at.saturating_add(DAY_SECS) > now
            && spend.nonce == payment.nonce
            && spend.token == payment.token
            && &spend.to == to_text
            && spend.units == payment.units
    });
    let worst = payment.worst_fee_wei();
    let counted = match replaces {
        Some(index) => Counted { micros: 0, fee_wei: worst.saturating_sub(info.spends[index].fee_wei), replaces },
        None => Counted { micros: payment.micros, fee_wei: worst, replaces: None },
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
    if fees.saturating_add(counted.fee_wei) > caps.daily_fees_wei {
        return Err(VaultError::OverCap(format!(
            "its fees could reach {} ETH, bringing the last 24 hours to {} ETH, over this wallet's daily fee cap of {} ETH",
            decimal(worst as u128, 18),
            decimal(fees.saturating_add(counted.fee_wei) as u128, 18),
            decimal(caps.daily_fees_wei as u128, 18)
        )));
    }
    if replaces.is_none() && info.in_window(now).count() >= MAX_SPENDS {
        return Err(VaultError::OverCap(format!("{MAX_SPENDS} payments in the last 24 hours is the most a wallet signs")));
    }
    Ok(counted)
}

/// Records a payment `decide` allowed: drops spends older than a day, then adds this one, or
/// raises the replaced one's fee to this worst case.
pub fn record(info: &mut WalletInfo, payment: &Payment, counted: Counted, now: u64) {
    let worst = payment.worst_fee_wei();
    if let Some(index) = counted.replaces {
        let spend = &mut info.spends[index];
        spend.fee_wei = spend.fee_wei.max(worst);
    } else {
        info.spends.push(Spend {
            at: now,
            nonce: payment.nonce,
            token: payment.token,
            to: payment.to_text.clone(),
            units: payment.units,
            micros: payment.micros,
            fee_wei: worst,
        });
    }
    info.spends.retain(|spend| spend.at.saturating_add(DAY_SECS) > now);
}
