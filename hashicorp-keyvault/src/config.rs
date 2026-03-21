//! Vault connection and authentication configuration.
//!
//! [`VaultConfig`] combines the server connection details (address, namespace,
//! TLS) with an [`AuthMethod`] that describes *how* to authenticate.
//!
//! ## Environment variables
//!
//! | Variable | Field | Default |
//! |---|---|---|
//! | `VAULT_ADDR` | `address` | `http://127.0.0.1:8200` |
//! | `VAULT_TOKEN` | auth method token | *(required for `from_env`)* |
//! | `VAULT_NAMESPACE` | `namespace` | `None` |
//! | `VAULT_CACERT` | `ca_cert_path` | `None` |
//!
//! ## Examples
//!
//! Token from environment:
//! ```rust,no_run
//! use hashicorp_keyvault::VaultConfig;
//! let config = VaultConfig::from_env().expect("VAULT_TOKEN must be set");
//! ```
//!
//! Explicit token:
//! ```rust
//! use hashicorp_keyvault::{VaultConfig, AuthMethod};
//! let config = VaultConfig::new("http://127.0.0.1:8200", AuthMethod::token("s.mytoken"));
//! ```
//!
//! AppRole (Role ID + Secret ID):
//! ```rust
//! use hashicorp_keyvault::{VaultConfig, AuthMethod};
//! let config = VaultConfig::new(
//!     "http://127.0.0.1:8200",
//!     AuthMethod::approle("5cb98310-6d34-ce08-2ddd-d8d1c612f9e1", "my-secret-id"),
//! );
//! ```

use std::env;

use crate::{
    auth::AuthMethod,
    error::{Result, SecretError},
};

/// The default Vault server address used when `VAULT_ADDR` is not set.
pub const DEFAULT_VAULT_ADDR: &str = "http://127.0.0.1:8200";

/// Connection and authentication configuration for a Vault server.
///
/// Holds the server address, TLS settings, optional namespace, and the
/// [`AuthMethod`] used to obtain a Vault token.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Base URL of the Vault server, e.g. `https://vault.example.com:8200`.
    pub address: String,

    /// How to authenticate to Vault. See [`AuthMethod`] for all options.
    pub auth: AuthMethod,

    /// Optional Vault namespace (Enterprise / HCP Vault).
    /// Sent as the `X-Vault-Namespace` HTTP header on every request.
    pub namespace: Option<String>,

    /// Optional path to a PEM-encoded CA certificate for TLS verification.
    /// Use when Vault is behind a private CA.
    pub ca_cert_path: Option<String>,

    /// Optional KV mount path (bucket path), e.g. `kv/data/myapp`.
    /// Defaults to `"secret"` if not set.
    pub mount_path: Option<String>,
}

impl VaultConfig {
    /// Create a config with an explicit address and auth method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::{VaultConfig, AuthMethod};
    ///
    /// // Token auth
    /// let config = VaultConfig::new("http://127.0.0.1:8200", AuthMethod::token("s.mytoken"));
    ///
    /// // AppRole auth
    /// let config = VaultConfig::new(
    ///     "http://127.0.0.1:8200",
    ///     AuthMethod::approle("role-id", "secret-id"),
    /// );
    /// ```
    pub fn new(address: impl Into<String>, auth: AuthMethod) -> Self {
        Self {
            address: address.into(),
            auth,
            namespace: None,
            ca_cert_path: None,
            mount_path: None,
        }
    }

    /// Load configuration from the standard Vault environment variables.
    ///
    /// Uses [`AuthMethod::Token`] with the value of `VAULT_TOKEN`.
    ///
    /// | Variable | Used for |
    /// |---|---|
    /// | `VAULT_ADDR` | Server address (defaults to `http://127.0.0.1:8200`) |
    /// | `VAULT_TOKEN` | Auth token (**required**) |
    /// | `VAULT_NAMESPACE` | Namespace (optional) |
    /// | `VAULT_CACERT` | CA certificate path (optional) |
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Storage`] if `VAULT_TOKEN` is not set.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use hashicorp_keyvault::VaultConfig;
    ///
    /// std::env::set_var("VAULT_TOKEN", "s.mytoken");
    /// let config = VaultConfig::from_env().unwrap();
    /// ```
    pub fn from_env() -> Result<Self> {
        let token = env::var("VAULT_TOKEN").map_err(|_| {
            SecretError::storage(
                "VAULT_TOKEN environment variable is not set; \
                 provide it or use VaultConfig::new() to pass credentials explicitly",
            )
        })?;

        Ok(Self {
            address: env::var("VAULT_ADDR").unwrap_or_else(|_| DEFAULT_VAULT_ADDR.to_string()),
            auth: AuthMethod::token(token),
            namespace: env::var("VAULT_NAMESPACE").ok(),
            ca_cert_path: env::var("VAULT_CACERT").ok(),
            mount_path: None,
        })
    }

    /// Load address, namespace, and CA cert from environment variables, but
    /// use the supplied `auth` method instead of `VAULT_TOKEN`.
    ///
    /// Useful when credentials come from a secrets manager or CI injection
    /// while the server address is still configured via environment.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use hashicorp_keyvault::{VaultConfig, AuthMethod};
    ///
    /// // AppRole credentials injected by CI; address from env
    /// let config = VaultConfig::from_env_with_auth(
    ///     AuthMethod::approle("role-id", "secret-id")
    /// );
    /// ```
    pub fn from_env_with_auth(auth: AuthMethod) -> Self {
        Self {
            address: env::var("VAULT_ADDR").unwrap_or_else(|_| DEFAULT_VAULT_ADDR.to_string()),
            auth,
            namespace: env::var("VAULT_NAMESPACE").ok(),
            ca_cert_path: env::var("VAULT_CACERT").ok(),
            mount_path: None,
        }
    }

    // ── builder helpers ───────────────────────────────────────────────────

    /// Set the Vault namespace (Enterprise / HCP Vault).
    ///
    /// ```rust
    /// use hashicorp_keyvault::{VaultConfig, AuthMethod};
    ///
    /// let config = VaultConfig::new("http://127.0.0.1:8200", AuthMethod::token("t"))
    ///     .with_namespace("admin");
    /// assert_eq!(config.namespace.as_deref(), Some("admin"));
    /// ```
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Set the path to a PEM-encoded CA certificate for TLS verification.
    ///
    /// ```rust
    /// use hashicorp_keyvault::{VaultConfig, AuthMethod};
    ///
    /// let config = VaultConfig::new("https://vault.example.com:8200", AuthMethod::token("t"))
    ///     .with_ca_cert_path("/etc/vault/ca.pem");
    /// assert_eq!(config.ca_cert_path.as_deref(), Some("/etc/vault/ca.pem"));
    /// ```
    pub fn with_ca_cert_path(mut self, path: impl Into<String>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// Set the KV mount / bucket path (e.g. `"kv/data/myapp"`).
    ///
    /// ```rust
    /// use hashicorp_keyvault::{VaultConfig, AuthMethod};
    ///
    /// let config = VaultConfig::new("http://127.0.0.1:8200", AuthMethod::token("t"))
    ///     .with_mount_path("kv/data/xorai/dm-meta");
    /// assert_eq!(config.mount_path.as_deref(), Some("kv/data/xorai/dm-meta"));
    /// ```
    pub fn with_mount_path(mut self, path: impl Into<String>) -> Self {
        self.mount_path = Some(path.into());
        self
    }

    // ── accessors ─────────────────────────────────────────────────────────

    /// Returns the server address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns a reference to the configured auth method.
    pub fn auth(&self) -> &AuthMethod {
        &self.auth
    }

    /// Returns the namespace, if set.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Returns the CA certificate path, if set.
    pub fn ca_cert_path(&self) -> Option<&str> {
        self.ca_cert_path.as_deref()
    }

    /// Returns the KV mount path, defaulting to `"secret"`.
    pub fn effective_mount_path(&self) -> &str {
        self.mount_path.as_deref().unwrap_or("secret")
    }
}

/// Redact all sensitive credential fields from `Display` output.
impl std::fmt::Display for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VaultConfig {{ address: {}, auth: {}, namespace: {:?}, mount: {:?} }}",
            self.address,
            self.auth, // AuthMethod::Display also redacts secrets
            self.namespace,
            self.mount_path,
        )
    }
}
