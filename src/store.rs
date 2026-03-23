//! The primary API surface: [`SecretStore`].

use std::collections::HashMap;

use chrono::Utc;

use crate::{
    auth::AuthMethod,
    config::{VaultConfig, DEFAULT_VAULT_ADDR},
    error::{Result, SecretError},
    secret::{Secret, SecretInfo},
};

/// Maximum allowed byte length for a key.
const MAX_KEY_LEN: usize = 256;

/// Maximum allowed byte length for a secret value (1 MiB).
const MAX_VALUE_LEN: usize = 1024 * 1024;

/// An in-memory store for secrets backed by a [`VaultConfig`].
///
/// Provides create, read, update, delete, list, and tag operations.
/// All mutating methods return a [`Result`] so every failure path must be
/// handled explicitly by the caller.
///
/// # Credentials
///
/// A [`VaultConfig`] is required. Supply credentials explicitly or load them
/// from the standard Vault environment variables:
///
/// ```rust,no_run
/// use hashicorp_keyvault::{SecretStore, VaultConfig};
///
/// // From environment (VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, VAULT_CACERT)
/// let config = VaultConfig::from_env().unwrap();
/// let mut store = SecretStore::with_config(config);
///
/// // Explicit credentials
/// let mut store = SecretStore::with_config(
///     VaultConfig::new("http://127.0.0.1:8200", "s.mytoken")
/// );
/// ```
///
/// # Key rules
///
/// - Non-empty, at most 256 bytes.
/// - Only alphanumeric characters and `-`, `_`, `/`, `.` are allowed.
///
/// # Value rules
///
/// - Non-empty, at most 1 MiB.
pub struct SecretStore {
    /// Connection and authentication configuration.
    config: VaultConfig,
    secrets: HashMap<String, Secret>,
}

impl SecretStore {
    /// Create a store with an explicit [`VaultConfig`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::{SecretStore, VaultConfig};
    ///
    /// let config = VaultConfig::new("http://127.0.0.1:8200", "s.mytoken");
    /// let mut store = SecretStore::with_config(config);
    /// ```
    pub fn with_config(config: VaultConfig) -> Self {
        Self { config, secrets: HashMap::new() }
    }

    /// Load credentials from environment variables and create a store.
    ///
    /// Reads `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, and `VAULT_CACERT`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Storage`] if `VAULT_TOKEN` is not set.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// // Requires VAULT_TOKEN to be set in the environment
    /// let mut store = SecretStore::from_env().unwrap();
    /// ```
    pub fn from_env() -> Result<Self> {
        Ok(Self::with_config(VaultConfig::from_env()?))
    }

    /// Return a reference to the active [`VaultConfig`].
    ///
    /// Useful for inspecting the address or namespace without exposing the token.
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    // ── write operations ──────────────────────────────────────────────────

    /// Store a new secret.
    ///
    /// # Errors
    ///
    /// - [`SecretError::InvalidKey`] — key fails length or character rules.
    /// - [`SecretError::InvalidValue`] — value is empty or exceeds 1 MiB.
    /// - [`SecretError::AlreadyExists`] — a secret with this key already exists.
    ///   Use [`update`](Self::update) or [`set`](Self::set) instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::{SecretStore, SecretError};
    ///
    /// let mut store = SecretStore::new();
    /// store.create("api/token", "abc123").unwrap();
    ///
    /// // Second create on the same key fails
    /// assert!(matches!(
    ///     store.create("api/token", "xyz").unwrap_err(),
    ///     SecretError::AlreadyExists { .. }
    /// ));
    /// ```
    pub fn create(&mut self, key: impl Into<String>, value: impl Into<String>) -> Result<SecretInfo> {
        let key = key.into();
        let value = value.into();

        validate_key(&key)?;
        validate_value(&key, &value)?;

        if self.secrets.contains_key(&key) {
            return Err(SecretError::already_exists(&key));
        }

        let secret = Secret::new(key.clone(), value);
        let info = SecretInfo::from(&secret);
        self.secrets.insert(key, secret);
        Ok(info)
    }

    /// Update the value of an existing secret.
    ///
    /// The version counter is incremented on every successful update.
    ///
    /// # Errors
    ///
    /// - [`SecretError::InvalidValue`] — value is empty or exceeds 1 MiB.
    /// - [`SecretError::NotFound`] — no secret exists for this key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let mut store = SecretStore::new();
    /// store.create("db/pass", "old").unwrap();
    ///
    /// let info = store.update("db/pass", "new").unwrap();
    /// assert_eq!(info.version, 2);
    /// ```
    pub fn update(&mut self, key: &str, value: impl Into<String>) -> Result<SecretInfo> {
        let value = value.into();
        validate_value(key, &value)?;

        let secret = self
            .secrets
            .get_mut(key)
            .ok_or_else(|| SecretError::not_found(key))?;

        secret.value = value;
        secret.metadata.updated_at = Utc::now();
        secret.metadata.version += 1;

        Ok(SecretInfo::from(&*secret))
    }

    /// Create the secret if it does not exist, or update it if it does.
    ///
    /// This is the upsert operation — it never returns
    /// [`AlreadyExists`](SecretError::AlreadyExists).
    ///
    /// # Errors
    ///
    /// - [`SecretError::InvalidKey`] — key fails validation.
    /// - [`SecretError::InvalidValue`] — value fails validation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let mut store = SecretStore::new();
    /// store.set("cfg/timeout", "30s").unwrap(); // creates
    /// store.set("cfg/timeout", "60s").unwrap(); // updates, version → 2
    /// assert_eq!(store.get_value("cfg/timeout").unwrap(), "60s");
    /// ```
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> Result<SecretInfo> {
        let key = key.into();
        let value = value.into();

        validate_key(&key)?;
        validate_value(&key, &value)?;

        if self.secrets.contains_key(&key) {
            // Validation already done above; update in place.
            let secret = self.secrets.get_mut(&key).unwrap();
            secret.value = value;
            secret.metadata.updated_at = Utc::now();
            secret.metadata.version += 1;
            Ok(SecretInfo::from(&*secret))
        } else {
            let secret = Secret::new(key.clone(), value);
            let info = SecretInfo::from(&secret);
            self.secrets.insert(key, secret);
            Ok(info)
        }
    }

    /// Delete a secret and return its metadata.
    ///
    /// # Errors
    ///
    /// - [`SecretError::NotFound`] — no secret exists for this key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let mut store = SecretStore::new();
    /// store.create("tmp/token", "xyz").unwrap();
    ///
    /// let info = store.delete("tmp/token").unwrap();
    /// assert_eq!(info.key, "tmp/token");
    /// assert!(!store.exists("tmp/token"));
    /// ```
    pub fn delete(&mut self, key: &str) -> Result<SecretInfo> {
        self.secrets
            .remove(key)
            .map(|s| SecretInfo::from(&s))
            .ok_or_else(|| SecretError::not_found(key))
    }

    // ── read operations ───────────────────────────────────────────────────

    /// Fetch the full secret entry (metadata + value) for a key.
    ///
    /// # Errors
    ///
    /// - [`SecretError::NotFound`] — no secret exists for this key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let mut store = SecretStore::new();
    /// store.create("svc/key", "secret").unwrap();
    ///
    /// let secret = store.get("svc/key").unwrap();
    /// println!("version: {}", secret.metadata.version);
    /// println!("value:   {}", secret.value);
    /// ```
    pub fn get(&self, key: &str) -> Result<&Secret> {
        self.secrets
            .get(key)
            .ok_or_else(|| SecretError::not_found(key))
    }

    /// Fetch only the plaintext value for a key.
    ///
    /// Shorthand for `store.get(key)?.value`.
    ///
    /// # Errors
    ///
    /// - [`SecretError::NotFound`] — no secret exists for this key.
    pub fn get_value(&self, key: &str) -> Result<&str> {
        Ok(&self.get(key)?.value)
    }

    /// Returns `true` if a secret with the given key exists.
    ///
    /// Does not return an error — use this for conditional logic without
    /// needing to handle a `Result`.
    pub fn exists(&self, key: &str) -> bool {
        self.secrets.contains_key(key)
    }

    // ── listing ───────────────────────────────────────────────────────────

    /// Return metadata for all secrets, sorted alphabetically by key.
    ///
    /// Values are intentionally excluded from the returned [`SecretInfo`]
    /// structs to prevent accidental exposure in logs or serialized output.
    pub fn list(&self) -> Vec<SecretInfo> {
        let mut infos: Vec<SecretInfo> = self.secrets.values().map(SecretInfo::from).collect();
        infos.sort_by(|a, b| a.key.cmp(&b.key));
        infos
    }

    /// Return all keys in sorted order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let mut store = SecretStore::new();
    /// store.create("z/key", "1").unwrap();
    /// store.create("a/key", "2").unwrap();
    ///
    /// assert_eq!(store.list_keys(), vec!["a/key", "z/key"]);
    /// ```
    pub fn list_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.secrets.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Total number of secrets currently in the store.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Returns `true` if the store contains no secrets.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    // ── tagging ───────────────────────────────────────────────────────────

    /// Add or replace a tag on a secret.
    ///
    /// Tags are arbitrary string key/value pairs useful for labelling secrets
    /// by environment, owner, rotation schedule, etc.
    ///
    /// # Errors
    ///
    /// - [`SecretError::NotFound`] — no secret exists for this key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let mut store = SecretStore::new();
    /// store.create("db/pass", "secret").unwrap();
    /// store.tag("db/pass", "env", "production").unwrap();
    /// ```
    pub fn tag(
        &mut self,
        key: &str,
        tag_key: impl Into<String>,
        tag_value: impl Into<String>,
    ) -> Result<()> {
        let secret = self
            .secrets
            .get_mut(key)
            .ok_or_else(|| SecretError::not_found(key))?;
        secret.metadata.tags.insert(tag_key.into(), tag_value.into());
        Ok(())
    }

    /// Remove a tag from a secret.
    ///
    /// This is a no-op if the tag key is not present — it does not error.
    ///
    /// # Errors
    ///
    /// - [`SecretError::NotFound`] — no secret exists for this key.
    pub fn untag(&mut self, key: &str, tag_key: &str) -> Result<()> {
        let secret = self
            .secrets
            .get_mut(key)
            .ok_or_else(|| SecretError::not_found(key))?;
        secret.metadata.tags.remove(tag_key);
        Ok(())
    }

    /// Find all secrets that have a specific tag key/value pair.
    ///
    /// Returns an empty `Vec` (not an error) when no secrets match.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// let mut store = SecretStore::new();
    /// store.create("prod/db", "secret1").unwrap();
    /// store.create("dev/db", "secret2").unwrap();
    /// store.tag("prod/db", "env", "production").unwrap();
    ///
    /// let results = store.find_by_tag("env", "production");
    /// assert_eq!(results.len(), 1);
    /// assert_eq!(results[0].key, "prod/db");
    /// ```
    pub fn find_by_tag(&self, tag_key: &str, tag_value: &str) -> Vec<SecretInfo> {
        self.secrets
            .values()
            .filter(|s| {
                s.metadata
                    .tags
                    .get(tag_key)
                    .map(|v| v == tag_value)
                    .unwrap_or(false)
            })
            .map(SecretInfo::from)
            .collect()
    }

    // ── vault integration ────────────────────────────────────────────────

    /// Fetch a secret value directly from HashiCorp Vault using AppRole auth.
    ///
    /// This method authenticates with AppRole and retrieves a secret from Vault.
    /// Supports KV v1 and v2 with automatic path fallback.
    ///
    /// # Parameters
    ///
    /// - `role_id`: AppRole Role ID
    /// - `secret_id`: AppRole Secret ID
    /// - `bucket_path`: Vault secret path (e.g., `kv/data/myapp` or `kv/myapp`)
    /// - `key`: Key name inside the secret
    /// - `approle_mount_path`: Optional custom AppRole mount path
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use hashicorp_keyvault::SecretStore;
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let store = SecretStore::new();
    /// let value = store.fetch_from_vault(
    ///     "my-role-id",
    ///     "my-secret-id",
    ///     "kv/data/myapp",
    ///     "password",
    ///     None,
    /// ).await.unwrap();
    /// # })
    /// ```
    pub async fn fetch_from_vault(
        &self,
        role_id: &str,
        secret_id: &str,
        bucket_path: &str,
        key: &str,
        approle_mount_path: Option<&str>,
    ) -> Result<String> {
        use crate::vault_client::VaultClient;

        let client = VaultClient::new(&self.config.address)?;
        let token = client.login_with_approle(role_id, secret_id, approle_mount_path).await?;
        client.fetch_secret_value(&token, bucket_path, key).await
    }
}

impl Default for SecretStore {
    /// Creates a store pointing at the default local Vault address with an
    /// empty token. Prefer [`SecretStore::from_env`] or
    /// [`SecretStore::with_config`] in production code.
    fn default() -> Self {
        Self::with_config(VaultConfig::new(
            DEFAULT_VAULT_ADDR,
            AuthMethod::token(""),
        ))
    }
}

// ── private validation helpers ────────────────────────────────────────────────

/// Validate a secret key against length and character rules.
fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(SecretError::invalid_key(key, "must not be empty"));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(SecretError::invalid_key(key, "must be 256 bytes or fewer"));
    }
    if !key
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '/' | '.'))
    {
        return Err(SecretError::invalid_key(
            key,
            "only alphanumeric characters and '-', '_', '/', '.' are allowed",
        ));
    }
    Ok(())
}

/// Validate a secret value against size rules.
fn validate_value(key: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(SecretError::invalid_value(key, "value must not be empty"));
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(SecretError::invalid_value(key, "value exceeds 1 MiB limit"));
    }
    Ok(())
}
