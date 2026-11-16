//! Tron keys, addresses and TRC-20 transfers, for a wallet the vault makes itself (#7490). Pure
//! functions; a new key is `evm::new_key` (the same secp256k1 scalar).
//!
//! The formats are the ones v1's agent wallets used (brennancheung/chain_pay `ChainPay.Tron.Address`,
//! `Tx`, `Signing`, `TRC20` and `Proto`):
//!
//! ```text
//! address    base58check(0x41 || the 20 bytes an Ethereum address of the same key has)
//! raw_data   protobuf Transaction.raw, fields in number order, zero values left out:
//!              1 ref_block_bytes (bytes 6-7 of the block number), 4 ref_block_hash (bytes 8-15
//!              of the block id), 8 expiration (ms), 11 contract, 14 timestamp (ms), 18 fee_limit (sun)
//! contract   Contract { 1 type: 31 (TriggerSmartContract),
//!                       2 parameter: Any { 1 "type.googleapis.com/protocol.TriggerSmartContract",
//!                                          2 TriggerSmartContract { 1 owner (21 bytes),
//!                                                                   2 token contract (21 bytes),
//!                                                                   4 transfer(to, amount) call data } } }
//!            call_value, token values and permission_id are all zero, so absent
//! txid       sha256(raw_data)
//! signature  r || s || v over the txid, v the recovery id 0 or 1 (java-tron's own layout)
//! signed     Transaction { 1 raw_data, 2 signature }: what /wallet/broadcasthex takes, in hex
//! ```
//!
//! **Fees.** A Tron transaction has no fee auction: the energy a TRC-20 transfer burns is priced by
//! the network (`getEnergyFee`), and `fee_limit` is only the most TRX it may burn for it. Bandwidth
//! (the signed bytes plus 64) is burned on top when the account's free allowance is used up, at
//! `getTransactionFee` sun a byte. So a transaction's worst case is `fee_limit` plus its bandwidth
//! at `BANDWIDTH_SUN_PER_BYTE`.

use sha2::{Digest, Sha256};

use crate::error::VaultError;
use crate::secret::SecretValue;

/// A Tron address's first byte, on mainnet and Nile alike.
pub const PREFIX: u8 = 0x41;
/// The longest a Tron transaction the vault signs may live: v1's 60 seconds (`expiration` minus
/// `timestamp`, and `expiration` at most this far past the vault's own clock, plus `CLOCK_SKEW_MS`).
pub const MAX_LIFE_MS: u64 = 60_000;
/// How far the caller's clock (the ref block's) may run from the vault's.
pub const CLOCK_SKEW_MS: u64 = 30_000;
/// Bandwidth's price, sun per byte (`getTransactionFee`, 1,000 since 2022), for a worst case.
pub const BANDWIDTH_SUN_PER_BYTE: u64 = 1_000;
/// What java-tron adds to a transaction's size for its bandwidth (`MAX_RESULT_SIZE_IN_TX`).
pub const BANDWIDTH_EXTRA_BYTES: u64 = 64;

const TRIGGER_SMART_CONTRACT: u64 = 31;
const TRIGGER_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let twice = sha256(&sha256(payload));
    [twice[0], twice[1], twice[2], twice[3]]
}

/// The `T...` form of an account's 20 bytes.
pub fn address_text(account: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(PREFIX);
    payload.extend_from_slice(account);
    let sum = checksum(&payload);
    payload.extend_from_slice(&sum);
    bs58::encode(payload).into_string()
}

/// Reads a `T...` address: base58, 25 bytes, the `0x41` prefix and a checksum that matches (a
/// mistyped address is refused). Answers the 20 bytes after the prefix.
pub fn parse_address(text: &str) -> Result<[u8; 20], VaultError> {
    let bad = |why: &str| VaultError::BadRequest(format!("the Tron address {why}"));
    let bytes = bs58::decode(text).into_vec().map_err(|_| bad("is base58, like T..."))?;
    if bytes.len() != 25 {
        return Err(bad("is 34 characters of base58, like T..."));
    }
    if bytes[0] != PREFIX {
        return Err(bad("starts with T (prefix 0x41)"));
    }
    if checksum(&bytes[..21]) != bytes[21..] {
        return Err(bad("has a checksum that doesn't match: check it was copied whole"));
    }
    let mut account = [0u8; 20];
    account.copy_from_slice(&bytes[1..21]);
    Ok(account)
}

/// The block reference of a block, from its number and its 32-byte id (TronGrid's `blockID`):
/// bytes 6-7 of the number and bytes 8-15 of the id (chain_pay's `Tx.ref_block`).
pub fn ref_block(number: u64, block_id: &[u8; 32]) -> ([u8; 2], [u8; 8]) {
    let be = number.to_be_bytes();
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&block_id[8..16]);
    ([be[6], be[7]], hash)
}

/// Checks a block id the caller gave: 64 hex digits whose first 8 bytes are the block's number,
/// as every Tron block id starts.
pub fn parse_block_id(text: &str, number: u64) -> Result<[u8; 32], VaultError> {
    let bad = || VaultError::BadRequest("ref_block_id is the block's 64-hex-digit blockID, starting with its number".into());
    let mut id = [0u8; 32];
    hex::decode_to_slice(text.trim_start_matches("0x"), &mut id).map_err(|_| bad())?;
    if id[..8] != number.to_be_bytes() {
        return Err(bad());
    }
    Ok(id)
}

// Protobuf, only as much as Transaction.raw needs: varints and length-delimited fields.

fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn field_varint(out: &mut Vec<u8>, field: u64, value: u64) {
    if value != 0 {
        varint(out, field << 3);
        varint(out, value);
    }
}

fn field_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    varint(out, (field << 3) | 2);
    varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn account_bytes(account: &[u8; 20]) -> [u8; 21] {
    let mut out = [0u8; 21];
    out[0] = PREFIX;
    out[1..].copy_from_slice(account);
    out
}

/// A TRC-20 `transfer(to, amount)` from the wallet, as the vault builds it: never from caller bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    /// The wallet's account (the signer).
    pub owner: [u8; 20],
    /// The token's contract.
    pub contract: [u8; 20],
    pub to: [u8; 20],
    pub units: u128,
    pub ref_block_bytes: [u8; 2],
    pub ref_block_hash: [u8; 8],
    /// Unix milliseconds.
    pub timestamp: u64,
    pub expiration: u64,
    /// The most TRX, in sun, the transfer may burn for energy.
    pub fee_limit: u64,
}

impl Transfer {
    /// `Transaction.raw`'s bytes: what the txid hashes and the signature signs.
    pub fn raw_data(&self) -> Vec<u8> {
        let mut trigger = Vec::with_capacity(120);
        field_bytes(&mut trigger, 1, &account_bytes(&self.owner));
        field_bytes(&mut trigger, 2, &account_bytes(&self.contract));
        field_bytes(&mut trigger, 4, &crate::evm::transfer_data(&self.to, self.units));
        let mut any = Vec::with_capacity(180);
        field_bytes(&mut any, 1, TRIGGER_URL.as_bytes());
        field_bytes(&mut any, 2, &trigger);
        let mut contract = Vec::with_capacity(190);
        field_varint(&mut contract, 1, TRIGGER_SMART_CONTRACT);
        field_bytes(&mut contract, 2, &any);
        let mut raw = Vec::with_capacity(230);
        field_bytes(&mut raw, 1, &self.ref_block_bytes);
        field_bytes(&mut raw, 4, &self.ref_block_hash);
        field_varint(&mut raw, 8, self.expiration);
        field_bytes(&mut raw, 11, &contract);
        field_varint(&mut raw, 14, self.timestamp);
        field_varint(&mut raw, 18, self.fee_limit);
        raw
    }

    /// The signed transaction's size: raw_data and one 65-byte signature, each length-delimited.
    pub fn signed_len(&self) -> u64 {
        let raw = self.raw_data().len() as u64;
        let mut prefix = Vec::new();
        varint(&mut prefix, raw);
        1 + prefix.len() as u64 + raw + 1 + 1 + 65
    }

    /// The most it can burn: `fee_limit` for energy, and its bandwidth at full price.
    pub fn worst_fee_sun(&self) -> u64 {
        let bandwidth = (self.signed_len() + BANDWIDTH_EXTRA_BYTES).saturating_mul(BANDWIDTH_SUN_PER_BYTE);
        self.fee_limit.saturating_add(bandwidth)
    }
}

/// A signed transaction: the whole `Transaction` protobuf (for `/wallet/broadcasthex`), its
/// raw_data and its txid.
#[derive(Clone, Debug)]
pub struct Signed {
    pub raw: Vec<u8>,
    pub raw_data: Vec<u8>,
    pub txid: [u8; 32],
}

/// Signs a transfer with the wallet's key, checked by recovering the signer and comparing it with
/// the wallet's account (`evm::sign_digest`).
pub fn sign(transfer: &Transfer, key: &SecretValue) -> Result<Signed, VaultError> {
    let raw_data = transfer.raw_data();
    let txid = sha256(&raw_data);
    let (rs, recovery) = crate::evm::sign_digest(&txid, key, &transfer.owner)?;
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&rs);
    signature[64] = recovery;
    let mut raw = Vec::with_capacity(raw_data.len() + 72);
    field_bytes(&mut raw, 1, &raw_data);
    field_bytes(&mut raw, 2, &signature);
    Ok(Signed { raw, raw_data, txid })
}
