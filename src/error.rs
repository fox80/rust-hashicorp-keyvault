//! Error types for the secret store.
//!
//! All fallible operations return [`Result<T>`], a type alias for
//! `std::result::Result<T, SecretError>`.
//!
//! ## Matching errors
//!
//! ```rust
//! use hashicorp_keyvault::{SecretStore, SecretError};
//!
//! let store = SecretStore::new();
//!
//! match store.get("missing/key") {
//!     Ok(secret) => println!("value: {}", secret.value),
//!     Err(SecretError::NotFound { key }) => eprintln!("'{key}' not found"),
//!     Err(e) => eprintln!("error: {e}"),
//! }
//! ```

use thiserror::Error;

/// All errors that can be returned by the secret store.
///
/// The enum is `#[non_exhaustive]` — new variants may be added in future
/// releases without it being a breaking change for downstream crates.
/// Always include a wildcard arm (`Err(e) => ...`) when matching.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretError {
    /// The requested key does not exist in the store.
    ///
    /// Returned by: [`get`](crate::store::SecretStore::get),
    /// [`get_value`](crate::store::SecretStore::get_value),
    /// [`update`](crate::store::SecretStore::update),
    /// [`delete`](crate::store::SecretStore::delete),
    /// [`tag`](crate::store::SecretStore::tag),
    /// [`untag`](crate::store::SecretStore::untag).
    #[error("secret not found: '{key}'")]
    NotFound { key: String },

    /// A secret with this key already exists.
    ///
    /// Use [`update`](crate::store::SecretStore::update) to change the value,
    /// or [`set`](crate::store::SecretStore::set) for upsert semantics.
    ///
    /// Returned by: [`create`](crate::store::SecretStore::create).
    #[error("secret already exists: '{key}'")]
    AlreadyExists { key: String },

    /// The supplied key string failed validation.
    ///
    /// Keys must be non-empty, at most 256 bytes, and contain only
    /// alphanumeric characters or `-`, `_`, `/`, `.`.
    #[error("invalid key '{key}': {reason}")]
    InvalidKey { key: String, reason: &'static str },

    /// The supplied value string failed validation.
    ///
    /// Values must be non-empty and at most 1 MiB (1,048,576 bytes).
    #[error("invalid value for key '{key}': {reason}")]
    InvalidValue { key: String, reason: &'static str },

    /// A serde JSON serialization or deserialization failure.
    ///
    /// Automatically constructed via `#[from]` when a `serde_json::Error`
    /// is converted with `?`.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A backend or storage-layer failure.
    ///
    /// The optional `source` field preserves the underlying cause so the full
    /// error chain remains accessible via [`std::error::Error::source`].
    ///
    /// Construct with [`SecretError::storage`] or
    /// [`SecretError::storage_caused_by`].
    #[error("storage error: {message}")]
    Storage {
        message: String,
        /// The underlying cause, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
}

impl SecretError {
    // ── convenience constructors ──────────────────────────────────────────

    /// Create a [`NotFound`](SecretError::NotFound) error for the given key.
    pub fn not_found(key: impl Into<String>) -> Self {
        Self::NotFound { key: key.into() }
    }

    /// Create an [`AlreadyExists`](SecretError::AlreadyExists) error for the given key.
    pub fn already_exists(key: impl Into<String>) -> Self {
        Self::AlreadyExists { key: key.into() }
    }

    /// Create an [`InvalidKey`](SecretError::InvalidKey) error with a static reason string.
    pub fn invalid_key(key: impl Into<String>, reason: &'static str) -> Self {
        Self::InvalidKey { key: key.into(), reason }
    }

    /// Create an [`InvalidValue`](SecretError::InvalidValue) error with a static reason string.
    pub fn invalid_value(key: impl Into<String>, reason: &'static str) -> Self {
        Self::InvalidValue { key: key.into(), reason }
    }

    /// Create a [`Storage`](SecretError::Storage) error with no underlying source.
    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage { message: message.into(), source: None }
    }

    /// Create a [`Storage`](SecretError::Storage) error that wraps an underlying cause.
    ///
    /// The source is accessible via [`std::error::Error::source`], enabling
    /// full error-chain inspection.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretError;
    /// use std::error::Error;
    ///
    /// let io_err = std::io::Error::new(std::io::ErrorKind::Other, "disk full");
    /// let err = SecretError::storage_caused_by("write failed", io_err);
    ///
    /// println!("{err}");                          // "storage error: write failed"
    /// println!("{}", err.source().unwrap());      // "disk full"
    /// ```
    pub fn storage_caused_by(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Storage {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    // ── classification helpers ────────────────────────────────────────────

    /// Returns `true` if this error indicates the requested key was not found.
    ///
    /// Useful when you want to handle the missing-key case without a full
    /// `match` expression.
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let store = SecretStore::new();
    /// let err = store.get("no-such-key").unwrap_err();
    /// assert!(err.is_not_found());
    /// ```
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Returns `true` if this error is a validation failure (invalid key or value).
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let mut store = SecretStore::new();
    /// let err = store.create("", "value").unwrap_err();
    /// assert!(err.is_validation());
    /// ```
    pub fn is_validation(&self) -> bool {
        matches!(self, Self::InvalidKey { .. } | Self::InvalidValue { .. })
    }
}

/// Convenience alias — all store operations return this type.
pub type Result<T> = std::result::Result<T, SecretError>;
