//! Ethereum (EVM) keys, addresses and transactions, for a wallet the vault makes itself (#7440).
//! Pure functions, no I/O apart from the random bytes of a new key.
//!
//! The formats are the ones v1's agent wallets used (brennancheung/chain_pay `ChainPay.EVM.Tx`,
//! `Signing`, `Address` and `ERC20`):
//!
//! ```text
//! address   last 20 bytes of keccak256(uncompressed public key without its 0x04)
//! unsigned  0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//!                        gas_limit, to, value, data, access_list])
//! signed    0x02 || rlp([... the same nine ..., y_parity, r, s])
//! hash      keccak256(signed)
//! transfer  data = a9059cbb || 12 zero bytes || recipient (20) || amount (uint256)
//! ```
//!
//! The private key is read here only, in `sign` and `address_of_key`: from the record's
//! `SecretValue` into k256's `SigningKey`, which wipes itself when dropped (R1). No function
//! here returns it or anything derived from it but the public address and signatures.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::error::VaultError;
use crate::secret::SecretValue;

/// `transfer(address,uint256)`'s selector: the first 4 bytes of its keccak256.
pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// A new private key: 32 random bytes from the operating system that are a valid secp256k1
/// scalar (not zero, below the group order; any other draw is thrown away and drawn again).
pub fn new_key() -> Result<SecretValue, VaultError> {
    for _ in 0..16 {
        let candidate = SecretValue::random(32)?;
        if SigningKey::from_slice(candidate.expose()).is_ok() {
            return Ok(candidate);
        }
    }
    Err(VaultError::Random)
}

fn signing_key(key: &SecretValue) -> Result<SigningKey, VaultError> {
    if key.len() != 32 {
        return Err(VaultError::VaultFileCorrupt);
    }
    SigningKey::from_slice(key.expose()).map_err(|_| VaultError::VaultFileCorrupt)
}

fn address_of(verifying: &VerifyingKey) -> [u8; 20] {
    let point = verifying.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// The address a private key controls.
pub fn address_of_key(key: &SecretValue) -> Result<[u8; 20], VaultError> {
    Ok(address_of(signing_key(key)?.verifying_key()))
}

/// The canonical form: lower-case `0x` hex, as the vault stores and compares addresses.
pub fn address_text(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

/// EIP-55 mixed case, for showing an address to a person.
pub fn checksummed(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = hex::encode(keccak256(lower.as_bytes()));
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (c, h) in lower.chars().zip(hash.chars()) {
        if c.is_ascii_alphabetic() && h.to_digit(16).unwrap_or(0) >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Reads an address: `0x` and 40 hex digits, all lower case, all upper case, or mixed case
/// only when its EIP-55 checksum matches (a mistyped mixed-case address is refused).
pub fn parse_address(text: &str) -> Result<[u8; 20], VaultError> {
    let bad = |why: &str| VaultError::BadRequest(format!("the address {why}"));
    let hex_part = text.strip_prefix("0x").ok_or_else(|| bad("starts with 0x"))?;
    if hex_part.len() != 40 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("is 0x and 40 hex digits"));
    }
    let mut address = [0u8; 20];
    hex::decode_to_slice(hex_part.to_ascii_lowercase(), &mut address).map_err(|_| bad("is 0x and 40 hex digits"))?;
    let all_lower = hex_part == hex_part.to_ascii_lowercase();
    let all_upper = hex_part == hex_part.to_ascii_uppercase();
    if !all_lower && !all_upper && checksummed(&address) != text {
        return Err(bad("has a mixed-case checksum that doesn't match: check it was copied whole"));
    }
    Ok(address)
}

/// An EIP-1559 (type 2) transaction with no value and no access list: the only kind the vault
/// signs is a token's `transfer`, built here from structured fields, never from caller bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u64,
    pub max_fee_per_gas: u64,
    pub gas_limit: u64,
    /// The token's contract.
    pub to: [u8; 20],
    /// The call data: always `transfer_data`.
    pub data: Vec<u8>,
}

/// The call data of `transfer(recipient, amount)`.
pub fn transfer_data(recipient: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&TRANSFER_SELECTOR);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(recipient);
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&amount.to_be_bytes());
    data
}

/// A signed transaction: its raw bytes for `eth_sendRawTransaction` and its hash.
#[derive(Clone, Debug)]
pub struct Signed {
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
}

// RLP, only as much as a type-2 transaction needs: byte strings, integers and lists.

fn rlp_length(out: &mut Vec<u8>, len: usize, short: u8) {
    if len < 56 {
        out.push(short + len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(short + 55 + (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

fn rlp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        rlp_length(out, bytes.len(), 0x80);
        out.extend_from_slice(bytes);
    }
}

/// An integer as its big-endian bytes with no leading zeros (zero is the empty string).
fn rlp_uint(out: &mut Vec<u8>, bytes: &[u8]) {
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    rlp_bytes(out, &bytes[skip..]);
}

fn rlp_list(out: &mut Vec<u8>, items: &[u8]) {
    rlp_length(out, items.len(), 0xc0);
    out.extend_from_slice(items);
}

impl Tx {
    fn fields(&self) -> Vec<u8> {
        let mut items = Vec::with_capacity(160);
        rlp_uint(&mut items, &self.chain_id.to_be_bytes());
        rlp_uint(&mut items, &self.nonce.to_be_bytes());
        rlp_uint(&mut items, &self.max_priority_fee_per_gas.to_be_bytes());
        rlp_uint(&mut items, &self.max_fee_per_gas.to_be_bytes());
        rlp_uint(&mut items, &self.gas_limit.to_be_bytes());
        rlp_bytes(&mut items, &self.to);
        rlp_uint(&mut items, &[]); // value: 0
        rlp_bytes(&mut items, &self.data);
        rlp_list(&mut items, &[]); // access list: empty
        items
    }

    /// What is hashed for signing: `0x02 || rlp(fields)`.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = vec![2u8];
        rlp_list(&mut out, &self.fields());
        out
    }

    fn encode_signed(&self, y_parity: u8, r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut items = self.fields();
        rlp_uint(&mut items, &[y_parity]);
        rlp_uint(&mut items, r);
        rlp_uint(&mut items, s);
        let mut out = vec![2u8];
        rlp_list(&mut out, &items);
        out
    }
}

/// Signs a transaction with a wallet's key: deterministic (RFC 6979), low-s, and checked by
/// recovering the signer from the signature and comparing it with `expected` (the address the
/// wallet record holds), so a signature the chain would read as someone else's never leaves.
pub fn sign(tx: &Tx, key: &SecretValue, expected: &[u8; 20]) -> Result<Signed, VaultError> {
    let failed = || VaultError::Io("signing failed".into());
    let signing = signing_key(key)?;
    let prehash = keccak256(&tx.signing_payload());
    let (signature, recovery): (Signature, RecoveryId) =
        signing.sign_prehash_recoverable(&prehash).map_err(|_| failed())?;
    drop(signing);
    // k256 already gives a low-s signature; normalize anyway, flipping the parity with it.
    let (signature, recovery) = match signature.normalize_s() {
        Some(low) => (low, RecoveryId::new(!recovery.is_y_odd(), recovery.is_x_reduced())),
        None => (signature, recovery),
    };
    let recovered = VerifyingKey::recover_from_prehash(&prehash, &signature, recovery).map_err(|_| failed())?;
    if &address_of(&recovered) != expected {
        return Err(failed());
    }
    let (r, s) = signature.split_bytes();
    let raw = tx.encode_signed(recovery.is_y_odd() as u8, &r, &s);
    let hash = keccak256(&raw);
    Ok(Signed { raw, hash })
}
