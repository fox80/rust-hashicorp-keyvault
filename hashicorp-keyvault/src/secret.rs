//! Core secret data types.
//!
//! - [`Secret`] — the full entry, including the plaintext value.
//! - [`SecretInfo`] — a value-free view, safe to return from listing operations.
//! - [`SecretMetadata`] — timestamps, version counter, and tags.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Metadata attached to every secret.
///
/// Stored alongside the value inside [`Secret`] and also embedded in
/// [`SecretInfo`] so callers can inspect it without accessing the value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Globally unique identifier (UUIDv4) assigned at creation time.
    pub id: String,

    /// The key used to look up this secret.
    pub key: String,

    /// UTC timestamp of when the secret was first created.
    pub created_at: DateTime<Utc>,

    /// UTC timestamp of the most recent value update.
    pub updated_at: DateTime<Utc>,

    /// Monotonically increasing counter. Starts at `1`, incremented on every
    /// successful [`update`](crate::store::SecretStore::update) or
    /// [`set`](crate::store::SecretStore::set).
    pub version: u32,

    /// Arbitrary string key/value pairs for labelling and querying.
    ///
    /// Managed via [`tag`](crate::store::SecretStore::tag),
    /// [`untag`](crate::store::SecretStore::untag), and
    /// [`find_by_tag`](crate::store::SecretStore::find_by_tag).
    pub tags: std::collections::HashMap<String, String>,
}

/// A complete secret entry: metadata plus the plaintext value.
///
/// Returned by [`get`](crate::store::SecretStore::get).
/// Never returned by listing operations — use [`SecretInfo`] for those.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Metadata: id, key, timestamps, version, tags.
    pub metadata: SecretMetadata,

    /// The plaintext secret value.
    pub value: String,
}

impl Secret {
    /// Create a new secret with version `1` and the current UTC timestamp.
    ///
    /// Prefer using [`SecretStore::create`](crate::store::SecretStore::create)
    /// rather than constructing this directly.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        let now = Utc::now();
        let key = key.into();
        Self {
            metadata: SecretMetadata {
                id: Uuid::new_v4().to_string(),
                key: key.clone(),
                created_at: now,
                updated_at: now,
                version: 1,
                tags: Default::default(),
            },
            value: value.into(),
        }
    }

    /// Builder-style helper to attach a tag at construction time.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::Secret;
    ///
    /// let secret = Secret::new("api/key", "abc123")
    ///     .with_tag("env", "production")
    ///     .with_tag("owner", "platform-team");
    /// ```
    pub fn with_tag(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.metadata.tags.insert(k.into(), v.into());
        self
    }
}

/// A value-free snapshot of a secret, safe to return from listing operations.
///
/// Contains all [`SecretMetadata`] fields but deliberately omits the plaintext
/// value so bulk operations never accidentally expose sensitive data.
///
/// Returned by [`list`](crate::store::SecretStore::list),
/// [`create`](crate::store::SecretStore::create),
/// [`update`](crate::store::SecretStore::update),
/// [`set`](crate::store::SecretStore::set),
/// [`delete`](crate::store::SecretStore::delete), and
/// [`find_by_tag`](crate::store::SecretStore::find_by_tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInfo {
    /// Globally unique identifier (UUIDv4).
    pub id: String,
    /// The secret's lookup key.
    pub key: String,
    /// UTC creation timestamp.
    pub created_at: DateTime<Utc>,
    /// UTC last-updated timestamp.
    pub updated_at: DateTime<Utc>,
    /// Current version number.
    pub version: u32,
    /// Attached tags.
    pub tags: std::collections::HashMap<String, String>,
}

impl From<&Secret> for SecretInfo {
    fn from(s: &Secret) -> Self {
        Self {
            id: s.metadata.id.clone(),
            key: s.metadata.key.clone(),
            created_at: s.metadata.created_at,
            updated_at: s.metadata.updated_at,
            version: s.metadata.version,
            tags: s.metadata.tags.clone(),
        }
    }
}
