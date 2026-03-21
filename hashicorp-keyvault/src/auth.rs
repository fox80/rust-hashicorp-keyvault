//! Vault authentication method credentials.
//!
//! [`AuthMethod`] is an enum covering every supported Vault auth backend.
//! Pass one to [`VaultConfig::with_auth`](crate::config::VaultConfig::with_auth)
//! to configure how the client authenticates.
//!
//! ## Choosing an auth method
//!
//! | Scenario | Method |
//! |---|---|
//! | Direct token (dev / CI) | [`AuthMethod::Token`] |
//! | Machine-to-machine (recommended for services) | [`AuthMethod::AppRole`] |
//! | Human users with username + password | [`AuthMethod::UserPass`] |
//! | Mutual TLS / certificate-based | [`AuthMethod::TlsCert`] |
//! | Corporate directory (Active Directory) | [`AuthMethod::Ldap`] |
//! | GitHub personal access token | [`AuthMethod::GitHub`] |
//! | Workloads running inside Kubernetes | [`AuthMethod::Kubernetes`] |
//! | Workloads running on AWS (EC2 / IAM) | [`AuthMethod::AwsIam`] |
//! | Workloads running on GCP | [`AuthMethod::Gcp`] |
//! | OIDC / JWT (SSO, Workload Identity, etc.) | [`AuthMethod::Jwt`] |

/// All supported Vault authentication methods.
///
/// Each variant carries exactly the credentials that method requires.
/// See the variant-level docs for field descriptions and usage examples.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthMethod {
    /// Authenticate with a pre-existing Vault token.
    ///
    /// The simplest method — suitable for development, CI pipelines, or any
    /// situation where a token is already available.
    ///
    /// Vault env var: `VAULT_TOKEN`
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::Token {
    ///     token: "s.myRootOrServiceToken".into(),
    /// };
    /// ```
    Token {
        /// A Vault service token (prefix `s.`) or legacy token.
        token: String,
    },

    /// Authenticate via the AppRole method.
    ///
    /// Designed for machine-to-machine authentication. The `role_id` is
    /// non-secret and identifies the role; the `secret_id` is the credential
    /// and should be treated like a password.
    ///
    /// This is the method shown in the UI screenshot (Role ID + Secret ID).
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::AppRole {
    ///     role_id: "5cb98310-6d34-ce08-2ddd-d8d1c612f9e1".into(),
    ///     secret_id: "my-secret-id".into(),
    ///     mount_path: None, // defaults to "approle"
    /// };
    /// ```
    AppRole {
        /// The AppRole Role ID (non-sensitive, identifies the role).
        role_id: String,
        /// The AppRole Secret ID (sensitive, acts as the password).
        secret_id: String,
        /// Mount path of the AppRole auth method. Defaults to `"approle"`.
        mount_path: Option<String>,
    },

    /// Authenticate with a username and password.
    ///
    /// Suitable for human operators or simple service accounts. Requires the
    /// `userpass` auth method to be enabled on the Vault server.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::UserPass {
    ///     username: "alice".into(),
    ///     password: "correct-horse-battery-staple".into(),
    ///     mount_path: None, // defaults to "userpass"
    /// };
    /// ```
    UserPass {
        /// The Vault username.
        username: String,
        /// The Vault password.
        password: String,
        /// Mount path of the userpass auth method. Defaults to `"userpass"`.
        mount_path: Option<String>,
    },

    /// Authenticate using a TLS client certificate.
    ///
    /// The Vault server must have the `cert` auth method enabled and a
    /// matching certificate role configured. The client presents its cert
    /// during the TLS handshake.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::TlsCert {
    ///     cert_pem_path: "/etc/vault/client.crt".into(),
    ///     key_pem_path: "/etc/vault/client.key".into(),
    ///     mount_path: None, // defaults to "cert"
    /// };
    /// ```
    TlsCert {
        /// Path to the PEM-encoded client certificate file.
        cert_pem_path: String,
        /// Path to the PEM-encoded private key file.
        key_pem_path: String,
        /// Mount path of the cert auth method. Defaults to `"cert"`.
        mount_path: Option<String>,
    },

    /// Authenticate via LDAP (e.g. Active Directory).
    ///
    /// Requires the `ldap` auth method to be enabled and configured on the
    /// Vault server with your directory's connection details.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::Ldap {
    ///     username: "jdoe".into(),
    ///     password: "ldap-password".into(),
    ///     mount_path: None, // defaults to "ldap"
    /// };
    /// ```
    Ldap {
        /// The LDAP username (typically `sAMAccountName` or `uid`).
        username: String,
        /// The LDAP password.
        password: String,
        /// Mount path of the LDAP auth method. Defaults to `"ldap"`.
        mount_path: Option<String>,
    },

    /// Authenticate using a GitHub personal access token.
    ///
    /// Requires the `github` auth method to be enabled. The token must belong
    /// to a user in the configured GitHub organisation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::GitHub {
    ///     token: "ghp_xxxxxxxxxxxxxxxxxxxx".into(),
    ///     mount_path: None, // defaults to "github"
    /// };
    /// ```
    GitHub {
        /// A GitHub personal access token with `read:org` scope.
        token: String,
        /// Mount path of the GitHub auth method. Defaults to `"github"`.
        mount_path: Option<String>,
    },

    /// Authenticate from inside a Kubernetes pod using a service account JWT.
    ///
    /// The JWT is typically mounted at
    /// `/var/run/secrets/kubernetes.io/serviceaccount/token`.
    /// Requires the `kubernetes` auth method to be enabled on Vault.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::Kubernetes {
    ///     role: "my-app-role".into(),
    ///     // Pass the JWT directly, or read it from the mounted file
    ///     jwt: std::fs::read_to_string(
    ///         "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ///     ).unwrap_or_default(),
    ///     mount_path: None, // defaults to "kubernetes"
    /// };
    /// ```
    Kubernetes {
        /// The Vault role bound to this Kubernetes service account.
        role: String,
        /// The Kubernetes service account JWT.
        jwt: String,
        /// Mount path of the Kubernetes auth method. Defaults to `"kubernetes"`.
        mount_path: Option<String>,
    },

    /// Authenticate from an AWS workload using IAM credentials.
    ///
    /// Supports both EC2 instance identity documents and IAM role credentials.
    /// Requires the `aws` auth method to be enabled on Vault.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::AwsIam {
    ///     role: "my-aws-role".into(),
    ///     access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
    ///     secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
    ///     session_token: None, // required for temporary credentials (STS)
    ///     region: Some("us-east-1".into()),
    ///     mount_path: None, // defaults to "aws"
    /// };
    /// ```
    AwsIam {
        /// The Vault role to authenticate against.
        role: String,
        /// AWS access key ID.
        access_key_id: String,
        /// AWS secret access key.
        secret_access_key: String,
        /// AWS session token — required when using temporary STS credentials.
        session_token: Option<String>,
        /// AWS region used to sign the STS request. Defaults to `"us-east-1"`.
        region: Option<String>,
        /// Mount path of the AWS auth method. Defaults to `"aws"`.
        mount_path: Option<String>,
    },

    /// Authenticate from a GCP workload using a signed JWT.
    ///
    /// Supports both GCE instance identity tokens and IAM service account
    /// JWTs. Requires the `gcp` auth method to be enabled on Vault.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::Gcp {
    ///     role: "my-gcp-role".into(),
    ///     jwt: "eyJhbGci...".into(),
    ///     mount_path: None, // defaults to "gcp"
    /// };
    /// ```
    Gcp {
        /// The Vault role to authenticate against.
        role: String,
        /// A GCP-signed JWT (GCE identity token or IAM service account JWT).
        jwt: String,
        /// Mount path of the GCP auth method. Defaults to `"gcp"`.
        mount_path: Option<String>,
    },

    /// Authenticate using a JWT or OIDC token.
    ///
    /// Covers OIDC providers (Okta, Auth0, Azure AD, Google, etc.) and any
    /// system that issues standard JWTs (e.g. GitHub Actions OIDC, GitLab CI).
    /// Requires the `jwt` auth method to be enabled on Vault.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashicorp_keyvault::AuthMethod;
    ///
    /// let auth = AuthMethod::Jwt {
    ///     role: "my-jwt-role".into(),
    ///     token: "eyJhbGci...".into(),
    ///     mount_path: None, // defaults to "jwt"
    /// };
    /// ```
    Jwt {
        /// The Vault role to authenticate against.
        role: String,
        /// The JWT or OIDC token issued by the identity provider.
        token: String,
        /// Mount path of the JWT/OIDC auth method. Defaults to `"jwt"`.
        mount_path: Option<String>,
    },
}

impl AuthMethod {
    // ── convenience constructors ──────────────────────────────────────────

    /// Create a [`Token`](AuthMethod::Token) credential.
    pub fn token(token: impl Into<String>) -> Self {
        Self::Token { token: token.into() }
    }

    /// Create an [`AppRole`](AuthMethod::AppRole) credential with the default mount path.
    pub fn approle(role_id: impl Into<String>, secret_id: impl Into<String>) -> Self {
        Self::AppRole {
            role_id: role_id.into(),
            secret_id: secret_id.into(),
            mount_path: None,
        }
    }

    /// Create a [`UserPass`](AuthMethod::UserPass) credential with the default mount path.
    pub fn userpass(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::UserPass {
            username: username.into(),
            password: password.into(),
            mount_path: None,
        }
    }

    /// Create a [`Kubernetes`](AuthMethod::Kubernetes) credential, reading the
    /// service account JWT from the standard in-cluster path automatically.
    ///
    /// Returns `None` if the token file cannot be read (i.e. not running inside
    /// a Kubernetes pod).
    pub fn kubernetes_from_pod(role: impl Into<String>) -> Option<Self> {
        let jwt = std::fs::read_to_string(
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        )
        .ok()?;
        Some(Self::Kubernetes {
            role: role.into(),
            jwt: jwt.trim().to_string(),
            mount_path: None,
        })
    }

    /// Return the effective mount path for this auth method.
    ///
    /// Uses the custom `mount_path` if set, otherwise returns the Vault default.
    pub fn mount_path(&self) -> &str {
        match self {
            Self::Token { .. } => "token",
            Self::AppRole { mount_path, .. } => mount_path.as_deref().unwrap_or("approle"),
            Self::UserPass { mount_path, .. } => mount_path.as_deref().unwrap_or("userpass"),
            Self::TlsCert { mount_path, .. } => mount_path.as_deref().unwrap_or("cert"),
            Self::Ldap { mount_path, .. } => mount_path.as_deref().unwrap_or("ldap"),
            Self::GitHub { mount_path, .. } => mount_path.as_deref().unwrap_or("github"),
            Self::Kubernetes { mount_path, .. } => mount_path.as_deref().unwrap_or("kubernetes"),
            Self::AwsIam { mount_path, .. } => mount_path.as_deref().unwrap_or("aws"),
            Self::Gcp { mount_path, .. } => mount_path.as_deref().unwrap_or("gcp"),
            Self::Jwt { mount_path, .. } => mount_path.as_deref().unwrap_or("jwt"),
        }
    }

    /// Human-readable name of the auth method (for logging, never includes secrets).
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token",
            Self::AppRole { .. } => "approle",
            Self::UserPass { .. } => "userpass",
            Self::TlsCert { .. } => "cert",
            Self::Ldap { .. } => "ldap",
            Self::GitHub { .. } => "github",
            Self::Kubernetes { .. } => "kubernetes",
            Self::AwsIam { .. } => "aws-iam",
            Self::Gcp { .. } => "gcp",
            Self::Jwt { .. } => "jwt",
        }
    }
}

/// Redact all sensitive fields from `Debug` output.
impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token { .. } =>
                write!(f, "AuthMethod::Token {{ token: [REDACTED] }}"),
            Self::AppRole { role_id, mount_path, .. } =>
                write!(f, "AuthMethod::AppRole {{ role_id: {role_id}, secret_id: [REDACTED], mount: {} }}", mount_path.as_deref().unwrap_or("approle")),
            Self::UserPass { username, mount_path, .. } =>
                write!(f, "AuthMethod::UserPass {{ username: {username}, password: [REDACTED], mount: {} }}", mount_path.as_deref().unwrap_or("userpass")),
            Self::TlsCert { cert_pem_path, key_pem_path, mount_path } =>
                write!(f, "AuthMethod::TlsCert {{ cert: {cert_pem_path}, key: {key_pem_path}, mount: {} }}", mount_path.as_deref().unwrap_or("cert")),
            Self::Ldap { username, mount_path, .. } =>
                write!(f, "AuthMethod::Ldap {{ username: {username}, password: [REDACTED], mount: {} }}", mount_path.as_deref().unwrap_or("ldap")),
            Self::GitHub { mount_path, .. } =>
                write!(f, "AuthMethod::GitHub {{ token: [REDACTED], mount: {} }}", mount_path.as_deref().unwrap_or("github")),
            Self::Kubernetes { role, mount_path, .. } =>
                write!(f, "AuthMethod::Kubernetes {{ role: {role}, jwt: [REDACTED], mount: {} }}", mount_path.as_deref().unwrap_or("kubernetes")),
            Self::AwsIam { role, access_key_id, region, mount_path, .. } =>
                write!(f, "AuthMethod::AwsIam {{ role: {role}, access_key_id: {access_key_id}, secret_access_key: [REDACTED], region: {:?}, mount: {} }}", region, mount_path.as_deref().unwrap_or("aws")),
            Self::Gcp { role, mount_path, .. } =>
                write!(f, "AuthMethod::Gcp {{ role: {role}, jwt: [REDACTED], mount: {} }}", mount_path.as_deref().unwrap_or("gcp")),
            Self::Jwt { role, mount_path, .. } =>
                write!(f, "AuthMethod::Jwt {{ role: {role}, token: [REDACTED], mount: {} }}", mount_path.as_deref().unwrap_or("jwt")),
        }
    }
}
