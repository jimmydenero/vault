//! Solana keys, addresses and SPL token transfers, for a wallet the vault makes itself (#7490).
//! Pure functions, no I/O apart from the random bytes of a new key.
//!
//! The formats are the ones v1's agent wallets used (brennancheung/platform-ops
//! `Wallets.Solana`), plus compute-budget instructions for a priority fee:
//!
//! ```text
//! key          a 32-byte Ed25519 seed (RFC 8032); the address is base58 of its public key
//! token acct   the wallet's associated token account (ATA) for a mint: the program-derived
//!              address of [owner, token program, mint] under the ATA program, i.e.
//!              sha256(owner || token program || mint || bump || ATA program || "ProgramDerivedAddress")
//!              at the first bump from 255 down that isn't a point on Ed25519
//! message      legacy: [1 signer, 0 read-only signers, n read-only others],
//!              compact(accounts) accounts, the recent blockhash, compact(instructions) instructions:
//!                ComputeBudget SetComputeUnitLimit  [2, u32 LE]
//!                ComputeBudget SetComputeUnitPrice  [3, u64 LE micro-lamports per compute unit]
//!                ATA CreateIdempotent               [1]  (the recipient's token account; when asked)
//!                Token TransferChecked              [12, u64 LE amount, u8 decimals]
//! transaction  compact(1) || Ed25519 signature of the message || message
//! ```
//!
//! **Fees.** 5,000 lamports for the one signature, plus the priority fee, the compute-unit price
//! times the limit (in millionths of a lamport, rounded up), plus, when the recipient's token
//! account is created, its rent (`TOKEN_ACCOUNT_RENT`), which the wallet pays and doesn't get
//! back. A transaction is valid while its recent blockhash is (about 150 blocks, a minute or two).
//!
//! The seed is read here only, in `signing_key`: from the record's `SecretValue` into
//! ed25519-dalek's `SigningKey`, which wipes itself when dropped (R1).

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::VaultError;
use crate::secret::SecretValue;

pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

/// What one signature costs, in lamports.
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
/// The rent of a token account (165 bytes), in lamports: what creating the recipient's costs.
pub const TOKEN_ACCOUNT_RENT: u64 = 2_039_280;
/// The compute units a transfer may be given: a `TransferChecked` with a `CreateIdempotent` takes
/// about 30,000 to 40,000.
pub const MIN_COMPUTE_UNITS: u32 = 1_000;
pub const MAX_COMPUTE_UNITS: u32 = 200_000;

/// A 32-byte account (an address) from its base58.
pub fn parse_address(text: &str) -> Result<[u8; 32], VaultError> {
    let bad = || VaultError::BadRequest("the Solana address is 32 bytes of base58".into());
    let bytes = bs58::decode(text).into_vec().map_err(|_| bad())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| bad())
}

/// A recent blockhash from its base58.
pub fn parse_blockhash(text: &str) -> Result<[u8; 32], VaultError> {
    parse_address(text).map_err(|_| VaultError::BadRequest("recent_blockhash is 32 bytes of base58".into()))
}

pub fn address_text(account: &[u8; 32]) -> String {
    bs58::encode(account).into_string()
}

fn program(text: &str) -> [u8; 32] {
    // The constants above are valid base58 of 32 bytes.
    parse_address(text).unwrap_or([0u8; 32])
}

/// Whether 32 bytes are an Ed25519 point: a program-derived address must not be one.
pub fn on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// The associated token account of `owner` for `mint` (the ATA program's derivation).
pub fn associated_token_account(owner: &[u8; 32], mint: &[u8; 32]) -> Result<[u8; 32], VaultError> {
    let token = program(TOKEN_PROGRAM);
    let ata = program(ATA_PROGRAM);
    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        hasher.update(owner);
        hasher.update(token);
        hasher.update(mint);
        hasher.update([bump]);
        hasher.update(ata);
        hasher.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = hasher.finalize().into();
        if !on_curve(&candidate) {
            return Ok(candidate);
        }
    }
    Err(VaultError::BadRequest("no associated token account exists for that owner and mint".into()))
}

/// A new key: a 32-byte Ed25519 seed from the operating system (every 32 bytes are one).
pub fn new_key() -> Result<SecretValue, VaultError> {
    SecretValue::random(32)
}

fn signing_key(key: &SecretValue) -> Result<SigningKey, VaultError> {
    if key.len() != 32 {
        return Err(VaultError::VaultFileCorrupt);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(key.expose());
    let signing = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing)
}

/// The address a key controls.
pub fn address_of_key(key: &SecretValue) -> Result<[u8; 32], VaultError> {
    Ok(signing_key(key)?.verifying_key().to_bytes())
}

fn compact(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// An SPL `TransferChecked` from the wallet's token account to the recipient's, as the vault builds
/// it: never from caller bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    /// The wallet (the signer and fee payer).
    pub owner: [u8; 32],
    /// The recipient's wallet; the tokens go to its associated token account.
    pub to: [u8; 32],
    pub mint: [u8; 32],
    pub decimals: u8,
    pub units: u64,
    pub recent_blockhash: [u8; 32],
    pub compute_unit_limit: u32,
    /// Micro-lamports per compute unit.
    pub compute_unit_price: u64,
    /// Whether to create the recipient's token account first (idempotent: nothing happens when
    /// it exists).
    pub create_recipient_account: bool,
}

impl Transfer {
    pub fn source(&self) -> Result<[u8; 32], VaultError> {
        associated_token_account(&self.owner, &self.mint)
    }

    pub fn destination(&self) -> Result<[u8; 32], VaultError> {
        associated_token_account(&self.to, &self.mint)
    }

    /// The priority fee in lamports: price times limit, in millionths, rounded up.
    pub fn priority_fee(&self) -> u64 {
        let micro = self.compute_unit_price as u128 * self.compute_unit_limit as u128;
        u64::try_from(micro.div_ceil(1_000_000)).unwrap_or(u64::MAX)
    }

    /// The most it can cost the wallet in lamports: the signature, the priority fee, and the
    /// recipient's token account's rent when it is created.
    pub fn worst_fee_lamports(&self) -> u64 {
        let rent = if self.create_recipient_account { TOKEN_ACCOUNT_RENT } else { 0 };
        LAMPORTS_PER_SIGNATURE.saturating_add(self.priority_fee()).saturating_add(rent)
    }

    /// The legacy message's bytes: what the signature signs.
    pub fn message(&self) -> Result<Vec<u8>, VaultError> {
        let source = self.source()?;
        let destination = self.destination()?;
        let token = program(TOKEN_PROGRAM);
        let budget = program(COMPUTE_BUDGET_PROGRAM);
        // Signer first, then writable, then read-only; each account once.
        let mut accounts: Vec<[u8; 32]> = vec![self.owner, source, destination];
        let writable = accounts.len();
        if self.create_recipient_account {
            accounts.extend([self.to, self.mint, program(SYSTEM_PROGRAM), token, program(ATA_PROGRAM), budget]);
        } else {
            accounts.extend([self.mint, token, budget]);
        }
        for (i, account) in accounts.iter().enumerate() {
            if accounts[..i].contains(account) {
                return Err(VaultError::BadRequest("the recipient is this wallet, its token account, or a program".into()));
            }
        }
        let index = |account: &[u8; 32]| accounts.iter().position(|a| a == account).unwrap_or(0) as u8;
        let mut instructions: Vec<(u8, Vec<u8>, Vec<u8>)> = Vec::with_capacity(4);
        let mut limit = vec![2u8];
        limit.extend_from_slice(&self.compute_unit_limit.to_le_bytes());
        instructions.push((index(&budget), Vec::new(), limit));
        let mut price = vec![3u8];
        price.extend_from_slice(&self.compute_unit_price.to_le_bytes());
        instructions.push((index(&budget), Vec::new(), price));
        if self.create_recipient_account {
            let metas = [self.owner, destination, self.to, self.mint, program(SYSTEM_PROGRAM), token];
            instructions.push((index(&program(ATA_PROGRAM)), metas.iter().map(index).collect(), vec![1u8]));
        }
        let mut transfer = vec![12u8];
        transfer.extend_from_slice(&self.units.to_le_bytes());
        transfer.push(self.decimals);
        instructions.push((index(&token), [source, self.mint, destination, self.owner].iter().map(index).collect(), transfer));

        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&[1, 0, (accounts.len() - writable) as u8]);
        compact(&mut out, accounts.len());
        for account in &accounts {
            out.extend_from_slice(account);
        }
        out.extend_from_slice(&self.recent_blockhash);
        compact(&mut out, instructions.len());
        for (program_index, metas, data) in &instructions {
            out.push(*program_index);
            compact(&mut out, metas.len());
            out.extend_from_slice(metas);
            compact(&mut out, data.len());
            out.extend_from_slice(data);
        }
        Ok(out)
    }
}

/// A signed transaction: its bytes (for `sendTransaction`, base64) and its signature, which is
/// also its id.
#[derive(Clone, Debug)]
pub struct Signed {
    pub raw: Vec<u8>,
    pub signature: [u8; 64],
}

/// Signs a transfer with the wallet's key: deterministic (RFC 8032), and checked against the
/// wallet's address (the key's public key must be `owner`, and the signature must verify) so a
/// signature the chain would refuse never leaves.
pub fn sign(transfer: &Transfer, key: &SecretValue) -> Result<Signed, VaultError> {
    let failed = || VaultError::Io("signing failed".into());
    let message = transfer.message()?;
    let signing = signing_key(key)?;
    let public = signing.verifying_key();
    let signature = signing.sign(&message);
    drop(signing);
    if public.to_bytes() != transfer.owner {
        return Err(failed());
    }
    let verifying = VerifyingKey::from_bytes(&transfer.owner).map_err(|_| failed())?;
    verifying.verify(&message, &signature).map_err(|_| failed())?;
    let signature = signature.to_bytes();
    let mut raw = Vec::with_capacity(1 + 64 + message.len());
    compact(&mut raw, 1);
    raw.extend_from_slice(&signature);
    raw.extend_from_slice(&message);
    Ok(Signed { raw, signature })
}
