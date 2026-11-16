//! Looks for a key in an API's reply before the agent sees it (R12). A debug or "who am I"
//! endpoint that echoes request headers would otherwise hand the key straight back.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::secret::SecretValue;

/// The forms of the key the vault searches for: as is, base64 (standard and URL-safe, with
/// and without padding), percent-encoded and hex (both cases).
/// This and `build_header` in proxy.rs are the proxy's call sites of `expose` in R1.
pub(crate) fn needles(key: &SecretValue) -> Vec<Zeroizing<Vec<u8>>> {
    let raw = key.expose();
    let mut forms: Vec<Zeroizing<Vec<u8>>> = vec![Zeroizing::new(raw.to_vec())];
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        forms.push(Zeroizing::new(engine.encode(raw).into_bytes()));
    }
    forms.push(Zeroizing::new(hex::encode(raw).into_bytes()));
    forms.push(Zeroizing::new(hex::encode_upper(raw).into_bytes()));
    for upper in [true, false] {
        let mut encoded = Vec::with_capacity(raw.len() * 3);
        for &b in raw {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                encoded.push(b);
            } else if upper {
                encoded.extend_from_slice(format!("%{b:02X}").as_bytes());
            } else {
                encoded.extend_from_slice(format!("%{b:02x}").as_bytes());
            }
        }
        forms.push(Zeroizing::new(encoded));
    }
    forms.retain(|form| !form.is_empty());
    forms.dedup_by(|a, b| a.as_slice() == b.as_slice());
    forms
}

/// Whether `haystack` contains any of the forms.
pub(crate) fn contains_any(haystack: &[u8], forms: &[Zeroizing<Vec<u8>>]) -> bool {
    forms.iter().any(|form| memchr::memmem::find(haystack, form).is_some())
}

/// R12 for a streamed reply: the reply goes to the caller as it arrives, so the check runs on
/// each piece together with the bytes held back from the one before. Only bytes that can't be the
/// start of a form of the key are released; a tail that could be (a proper prefix of a form) is
/// held until the next piece shows whether it is. A form split across two pieces is found
/// whole, and the caller never receives any form of the key: the stream stops before it. A reply
/// that ends in a held tail releases it at the end, since a proper prefix isn't the key.
pub(crate) struct StreamScrub {
    finders: Vec<memchr::memmem::Finder<'static>>,
    forms: Vec<Zeroizing<Vec<u8>>>,
    held: Zeroizing<Vec<u8>>,
}

/// A form of the key turned up in the reply.
pub(crate) struct Echo;

impl StreamScrub {
    pub(crate) fn new(key: &SecretValue) -> StreamScrub {
        let forms = needles(key);
        let finders = forms.iter().map(|form| memchr::memmem::Finder::new(form.as_slice()).into_owned()).collect();
        StreamScrub { finders, forms, held: Zeroizing::new(Vec::new()) }
    }

    /// Takes the next piece and returns the bytes that may go to the caller now.
    pub(crate) fn push(&mut self, piece: &[u8]) -> Result<Vec<u8>, Echo> {
        let mut window = std::mem::take(&mut *self.held);
        window.extend_from_slice(piece);
        if self.finders.iter().any(|finder| finder.find(&window).is_some()) {
            window.fill(0);
            return Err(Echo);
        }
        let keep = self.prefix_tail(&window);
        let tail = window.split_off(window.len() - keep);
        *self.held = tail;
        Ok(window)
    }

    /// The bytes still held when the reply ends.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.held)
    }

    /// The length of the longest tail of `window` that is a proper prefix of some form.
    fn prefix_tail(&self, window: &[u8]) -> usize {
        let mut keep = 0;
        for form in &self.forms {
            let longest = (form.len() - 1).min(window.len());
            for k in (keep + 1..=longest).rev() {
                let start = window.len() - k;
                if window[start] == form[0] && window[start..] == form[..k] {
                    keep = k;
                    break;
                }
            }
        }
        keep
    }
}
