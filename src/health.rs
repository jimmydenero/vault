//! Whether each credential of a kind with an entry in `kinds` works, has expired or was refused,
//! as the upstream's replies said (token upkeep, R39). Kept by secret id and version, so a
//! replaced or renewed value starts again at `unknown`. Names, states, times and statuses only:
//! never a value (R4). The daemon keeps the book in memory and writes it to `health.json` in the
//! vault folder when a state changes, so it survives a restart.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::kinds::{self, HealthState};
use crate::model::VaultDoc;
use crate::protocol::CredentialHealth;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Entry {
    version: u64,
    state: HealthState,
    at: String,
    status: Option<u16>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct HealthBook {
    entries: BTreeMap<String, Entry>,
}

impl HealthBook {
    pub fn from_json(bytes: &[u8]) -> HealthBook {
        serde_json::from_slice(bytes).unwrap_or_default()
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Records what a reply said about version `version` of secret `id`. Returns whether the
    /// state changed (the caller writes the book then).
    pub fn observe(&mut self, id: &str, version: u64, state: HealthState, status: Option<u16>, at: String) -> bool {
        let entry = Entry { version, state, at, status };
        match self.entries.insert(id.to_string(), entry) {
            Some(old) => old.version != version || old.state != state,
            None => true,
        }
    }

    /// Every credential of a kind with an entry in `kinds`, in the vault's order, with what the
    /// book knows of its current version. Entries of deleted secrets are left out.
    pub(crate) fn report(&self, doc: &VaultDoc) -> Vec<CredentialHealth> {
        doc.records
            .iter()
            .filter_map(|record| kinds::spec(record.kind).map(|spec| (record, spec)))
            .map(|(record, spec)| {
                let known = self.entries.get(&record.id).filter(|entry| entry.version == record.version);
                CredentialHealth {
                    id: record.id.clone(),
                    name: record.name.clone(),
                    kind: record.kind,
                    version: record.version,
                    state: known.map_or(HealthState::Unknown, |entry| entry.state),
                    checked_at: known.map(|entry| entry.at.clone()),
                    status: known.and_then(|entry| entry.status),
                    refresh: if spec.refresher.is_some() { "by_vault" } else { "never" }.into(),
                    expires_at: record.expires_at,
                }
            })
            .collect()
    }

    /// Drops the entries of secrets no longer in the vault.
    pub(crate) fn prune(&mut self, doc: &VaultDoc) -> bool {
        let before = self.entries.len();
        self.entries.retain(|id, _| doc.records.iter().any(|record| &record.id == id));
        self.entries.len() != before
    }
}
