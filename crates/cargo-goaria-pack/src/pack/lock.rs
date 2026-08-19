use serde::{Deserialize, Serialize};

pub const LOCK_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockFile {
    pub schema_version: u32,
    pub packs: Vec<LockEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockEntry {
    pub pack_id: String,
    pub pack_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_url: Option<String>,
    pub asset_path: String,
    pub asset_sha256: String,
    pub public_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_sha256: Option<String>,
}

impl LockFile {
    pub fn single_entry(entry: LockEntry) -> Self {
        Self {
            schema_version: LOCK_SCHEMA_VERSION,
            packs: vec![entry],
        }
    }

    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string_pretty(self)?;
        s.push('\n');
        Ok(s)
    }
}
