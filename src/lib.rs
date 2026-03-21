//! # hashicorp-keyvault
//!
//! A secret management library with full CRUD operations, versioning, and tagging.
//!
//! ## Credentials
//!
//! Credentials are supplied via [`VaultConfig`] + [`AuthMethod`]. Ten auth
//! methods are supported — pick the one that matches your environment:
//!
//! ```rust,no_run
//! use hashicorp_keyvault::{SecretStore, VaultConfig, AuthMethod};
//!
//! // Token (simplest)
//! let store = SecretStore::with_config(
//!     VaultConfig::new("http://127.0.0.1:8200", AuthMethod::token("s.mytoken"))
//! );
//!
//! // AppRole (recommended for services)
//! let store = SecretStore::with_config(
//!     VaultConfig::new("http://127.0.0.1:8200",
//!         AuthMethod::approle("role-id", "secret-id"))
//! );
//!
//! // From environment variables
//! let store = SecretStore::from_env().unwrap();
//! ```
//!
//! ## Modules
//!
//! - [`store`] — [`SecretStore`], the primary API surface
//! - [`auth`] — [`AuthMethod`] enum covering all Vault auth backends
//! - [`config`] — [`VaultConfig`] for connection settings
//! - [`secret`] — [`Secret`], [`SecretInfo`], [`SecretMetadata`] types
//! - [`error`] — [`SecretError`] and [`Result`](crate::error::Result)

pub mod auth;
pub mod config;
pub mod error;
pub mod secret;
pub mod store;

pub use auth::AuthMethod;
pub use config::VaultConfig;
pub use error::{Result, SecretError};
pub use secret::{Secret, SecretInfo, SecretMetadata};
pub use store::SecretStore;

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SecretStore {
        SecretStore::with_config(VaultConfig::new(
            "http://127.0.0.1:8200",
            AuthMethod::token("test-token"),
        ))
    }

    // ── basic CRUD ────────────────────────────────────────────────────────

    #[test]
    fn create_and_get() {
        let mut store = store();
        store.create("db/password", "s3cr3t").unwrap();
        assert_eq!(store.get_value("db/password").unwrap(), "s3cr3t");
    }

    #[test]
    fn duplicate_create_returns_already_exists() {
        let mut store = store();
        store.create("key", "v1").unwrap();
        let err = store.create("key", "v2").unwrap_err();
        assert!(matches!(err, SecretError::AlreadyExists { .. }));
        assert!(err.to_string().contains("key"));
    }

    #[test]
    fn get_missing_key_returns_not_found() {
        let store = store();
        let err = store.get("missing").unwrap_err();
        assert!(err.is_not_found());
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn update_bumps_version() {
        let mut store = store();
        store.create("key", "v1").unwrap();
        let info = store.update("key", "v2").unwrap();
        assert_eq!(info.version, 2);
        assert_eq!(store.get_value("key").unwrap(), "v2");
    }

    #[test]
    fn update_missing_key_returns_not_found() {
        let mut store = store();
        let err = store.update("ghost", "val").unwrap_err();
        assert!(err.is_not_found());
    }

    #[test]
    fn set_upserts() {
        let mut store = store();
        store.set("key", "v1").unwrap();
        let info = store.set("key", "v2").unwrap();
        assert_eq!(info.version, 2);
        assert_eq!(store.get_value("key").unwrap(), "v2");
    }

    #[test]
    fn delete_removes_key() {
        let mut store = store();
        store.create("key", "val").unwrap();
        store.delete("key").unwrap();
        assert!(!store.exists("key"));
    }

    #[test]
    fn delete_missing_key_returns_not_found() {
        let mut store = store();
        let err = store.delete("nope").unwrap_err();
        assert!(err.is_not_found());
    }

    // ── listing ───────────────────────────────────────────────────────────

    #[test]
    fn list_keys_sorted() {
        let mut store = store();
        store.create("z/key", "1").unwrap();
        store.create("a/key", "2").unwrap();
        store.create("m/key", "3").unwrap();
        assert_eq!(store.list_keys(), vec!["a/key", "m/key", "z/key"]);
    }

    #[test]
    fn list_does_not_expose_values() {
        let mut store = store();
        store.create("sec", "topsecret").unwrap();
        assert_eq!(store.list().len(), 1);
    }

    // ── tagging ───────────────────────────────────────────────────────────

    #[test]
    fn tag_and_find() {
        let mut store = store();
        store.create("svc/token", "abc").unwrap();
        store.tag("svc/token", "env", "prod").unwrap();
        let results = store.find_by_tag("env", "prod");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "svc/token");
    }

    #[test]
    fn untag_removes_tag() {
        let mut store = store();
        store.create("svc/token", "abc").unwrap();
        store.tag("svc/token", "env", "prod").unwrap();
        store.untag("svc/token", "env").unwrap();
        assert!(store.find_by_tag("env", "prod").is_empty());
    }

    #[test]
    fn tag_missing_key_returns_not_found() {
        let mut store = store();
        let err = store.tag("ghost", "k", "v").unwrap_err();
        assert!(err.is_not_found());
    }

    // ── key validation ────────────────────────────────────────────────────

    #[test]
    fn empty_key_rejected() {
        let mut store = store();
        let err = store.create("", "val").unwrap_err();
        assert!(err.is_validation());
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }

    #[test]
    fn key_with_spaces_rejected() {
        let mut store = store();
        let err = store.create("bad key!", "val").unwrap_err();
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }

    #[test]
    fn key_too_long_rejected() {
        let mut store = store();
        let long_key = "a".repeat(257);
        let err = store.create(&long_key, "val").unwrap_err();
        assert!(matches!(err, SecretError::InvalidKey { .. }));
    }

    // ── value validation ──────────────────────────────────────────────────

    #[test]
    fn empty_value_rejected() {
        let mut store = store();
        let err = store.create("key", "").unwrap_err();
        assert!(err.is_validation());
        assert!(matches!(err, SecretError::InvalidValue { .. }));
    }

    #[test]
    fn oversized_value_rejected() {
        let mut store = store();
        let big = "x".repeat(1024 * 1024 + 1);
        let err = store.create("key", big).unwrap_err();
        assert!(matches!(err, SecretError::InvalidValue { .. }));
    }

    #[test]
    fn update_with_empty_value_rejected() {
        let mut store = store();
        store.create("key", "v1").unwrap();
        let err = store.update("key", "").unwrap_err();
        assert!(matches!(err, SecretError::InvalidValue { .. }));
    }

    // ── config ────────────────────────────────────────────────────────────

    #[test]
    fn config_accessible_from_store() {
        let config = VaultConfig::new(
            "http://vault:8200",
            AuthMethod::token("s.token"),
        )
        .with_namespace("admin");
        let store = SecretStore::with_config(config);
        assert_eq!(store.config().address(), "http://vault:8200");
        assert_eq!(store.config().namespace(), Some("admin"));
        assert_eq!(store.config().auth().method_name(), "token");
    }

    #[test]
    fn from_env_fails_without_vault_token() {
        std::env::remove_var("VAULT_TOKEN");
        let err = SecretStore::from_env().unwrap_err();
        assert!(err.to_string().contains("VAULT_TOKEN"));
    }

    #[test]
    fn from_env_reads_vault_token() {
        std::env::set_var("VAULT_TOKEN", "env-token");
        std::env::set_var("VAULT_ADDR", "http://env-vault:8200");
        let store = SecretStore::from_env().unwrap();
        assert_eq!(store.config().address(), "http://env-vault:8200");
        assert_eq!(store.config().auth().method_name(), "token");
        std::env::remove_var("VAULT_TOKEN");
        std::env::remove_var("VAULT_ADDR");
    }

    #[test]
    fn config_display_redacts_secrets() {
        let config = VaultConfig::new(
            "http://127.0.0.1:8200",
            AuthMethod::approle("my-role-id", "super-secret"),
        );
        let display = config.to_string();
        assert!(!display.contains("super-secret"));
        assert!(display.contains("REDACTED"));
        assert!(display.contains("my-role-id")); // role_id is non-sensitive
    }

    // ── error helpers ─────────────────────────────────────────────────────

    #[test]
    fn storage_error_preserves_source() {
        use std::fmt;

        #[derive(Debug)]
        struct FakeIo;
        impl fmt::Display for FakeIo {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "disk full")
            }
        }
        impl std::error::Error for FakeIo {}

        let err = SecretError::storage_caused_by("write failed", FakeIo);
        assert!(err.to_string().contains("write failed"));
        use std::error::Error;
        assert!(err.source().is_some());
    }
}
