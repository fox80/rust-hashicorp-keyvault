# hashicorp-keyvault

A Rust library for managing secrets with full CRUD operations, versioning, and tagging.
Designed as a clean, ergonomic interface that mirrors the mental model of HashiCorp Vault's
KV secrets engine.

## Features

- Create, read, update, delete secrets
- Upsert (`set`) for create-or-update in one call
- Automatic version tracking on every write
- Tag secrets with arbitrary key/value metadata
- Query secrets by tag
- Safe listing — values are never exposed in list results
- Structured, matchable error types with full source-chain support
- Key and value validation with clear error messages

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hashicorp-keyvault = { path = "path/to/hashicorp-keyvault" }
```

---

## Credentials

A `VaultConfig` is required to create a store. It combines the server address
with an `AuthMethod` that describes how to authenticate.

### Supported auth methods

| Method | Best for | Constructor |
|---|---|---|
| `Token` | Dev, CI, direct token | `AuthMethod::token(t)` |
| `AppRole` | Services, automation (recommended) | `AuthMethod::approle(role_id, secret_id)` |
| `UserPass` | Human operators, simple accounts | `AuthMethod::userpass(user, pass)` |
| `TlsCert` | Mutual TLS, automated systems | `AuthMethod::TlsCert { .. }` |
| `Ldap` | Corporate Active Directory | `AuthMethod::Ldap { .. }` |
| `GitHub` | Developer workflows | `AuthMethod::GitHub { .. }` |
| `Kubernetes` | Workloads inside K8s pods | `AuthMethod::kubernetes_from_pod(role)` |
| `AwsIam` | EC2 / Lambda / ECS workloads | `AuthMethod::AwsIam { .. }` |
| `Gcp` | GCE / Cloud Run workloads | `AuthMethod::Gcp { .. }` |
| `Jwt` | OIDC / SSO / GitHub Actions | `AuthMethod::Jwt { .. }` |

---

### Token

The simplest method — use a pre-existing Vault token directly.

```rust
use hashicorp_keyvault::{SecretStore, VaultConfig, AuthMethod};

let store = SecretStore::with_config(
    VaultConfig::new("http://127.0.0.1:8200", AuthMethod::token("s.mytoken"))
);
```

---

### AppRole (Role ID + Secret ID)

Recommended for services and automation. The `role_id` is non-sensitive;
the `secret_id` is the credential. This is the method shown in the UI screenshot.

```rust
use hashicorp_keyvault::{SecretStore, VaultConfig, AuthMethod};

let store = SecretStore::with_config(
    VaultConfig::new(
        "https://hashicorp-agentic.xoral.com",
        AuthMethod::approle(
            "5cb98310-6d34-ce08-2ddd-d8d1c612f9e1",  // Role ID
            "my-secret-id",                            // Secret ID
        ),
    )
    .with_mount_path("kv/data/xorai/dm-meta"),         // Bucket path
);
```

Custom mount path for AppRole:

```rust
use hashicorp_keyvault::AuthMethod;

let auth = AuthMethod::AppRole {
    role_id: "my-role-id".into(),
    secret_id: "my-secret-id".into(),
    mount_path: Some("custom-approle-path".into()),
};
```

---

### Username + Password

```rust
use hashicorp_keyvault::{SecretStore, VaultConfig, AuthMethod};

let store = SecretStore::with_config(
    VaultConfig::new(
        "http://127.0.0.1:8200",
        AuthMethod::userpass("alice", "correct-horse-battery-staple"),
    )
);
```

---

### TLS Certificate

```rust
use hashicorp_keyvault::{VaultConfig, AuthMethod};

let config = VaultConfig::new(
    "https://vault.example.com:8200",
    AuthMethod::TlsCert {
        cert_pem_path: "/etc/vault/client.crt".into(),
        key_pem_path:  "/etc/vault/client.key".into(),
        mount_path: None, // defaults to "cert"
    },
)
.with_ca_cert_path("/etc/vault/ca.pem");
```

---

### LDAP / Active Directory

```rust
use hashicorp_keyvault::{VaultConfig, AuthMethod};

let config = VaultConfig::new(
    "https://vault.example.com:8200",
    AuthMethod::Ldap {
        username: "jdoe".into(),
        password: "ldap-password".into(),
        mount_path: None, // defaults to "ldap"
    },
);
```

---

### GitHub

```rust
use hashicorp_keyvault::{VaultConfig, AuthMethod};

let config = VaultConfig::new(
    "http://127.0.0.1:8200",
    AuthMethod::GitHub {
        token: "ghp_xxxxxxxxxxxxxxxxxxxx".into(),
        mount_path: None, // defaults to "github"
    },
);
```

---

### Kubernetes

Automatically reads the service account JWT from the standard in-cluster path:

```rust,no_run
use hashicorp_keyvault::{SecretStore, VaultConfig, AuthMethod};

let auth = AuthMethod::kubernetes_from_pod("my-app-role")
    .expect("not running inside a Kubernetes pod");

let store = SecretStore::with_config(
    VaultConfig::new("https://vault.example.com:8200", auth)
);
```

Or supply the JWT manually:

```rust
use hashicorp_keyvault::{VaultConfig, AuthMethod};

let config = VaultConfig::new(
    "https://vault.example.com:8200",
    AuthMethod::Kubernetes {
        role: "my-app-role".into(),
        jwt: "<service-account-jwt>".into(),
        mount_path: None,
    },
);
```

---

### AWS IAM

```rust
use hashicorp_keyvault::{VaultConfig, AuthMethod};

let config = VaultConfig::new(
    "https://vault.example.com:8200",
    AuthMethod::AwsIam {
        role: "my-aws-role".into(),
        access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,          // set this for STS / assumed-role credentials
        region: Some("us-east-1".into()),
        mount_path: None,
    },
);
```

---

### GCP

```rust
use hashicorp_keyvault::{VaultConfig, AuthMethod};

let config = VaultConfig::new(
    "https://vault.example.com:8200",
    AuthMethod::Gcp {
        role: "my-gcp-role".into(),
        jwt: "<gce-identity-or-iam-jwt>".into(),
        mount_path: None,
    },
);
```

---

### JWT / OIDC

Covers Okta, Auth0, Azure AD, Google, GitHub Actions OIDC, GitLab CI, etc.

```rust
use hashicorp_keyvault::{VaultConfig, AuthMethod};

let config = VaultConfig::new(
    "https://vault.example.com:8200",
    AuthMethod::Jwt {
        role: "my-jwt-role".into(),
        token: "<oidc-or-jwt-token>".into(),
        mount_path: None, // defaults to "jwt"
    },
);
```

---

### From environment variables

Reads `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`:

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="s.mytoken"
export VAULT_NAMESPACE="admin"       # optional
export VAULT_CACERT="/etc/vault/ca.pem"  # optional
```

```rust,no_run
use hashicorp_keyvault::SecretStore;

let mut store = SecretStore::from_env().expect("VAULT_TOKEN must be set");
```

### Mixed — auth from code, address from environment

```rust,no_run
use hashicorp_keyvault::{SecretStore, VaultConfig, AuthMethod};

// VAULT_ADDR and VAULT_NAMESPACE come from env; credentials are explicit
let config = VaultConfig::from_env_with_auth(
    AuthMethod::approle("role-id", "secret-id")
);
let mut store = SecretStore::with_config(config);
```

---

## Quick Start

```rust,no_run
use hashicorp_keyvault::{SecretStore, VaultConfig, AuthMethod, SecretError};

fn main() {
    // Load credentials from environment
    let mut store = SecretStore::from_env().unwrap();

    // Or pass them explicitly
    let mut store = SecretStore::with_config(
        VaultConfig::new("http://127.0.0.1:8200", AuthMethod::token("s.mytoken"))
    );

    store.create("db/password", "s3cr3t").unwrap();
    let value = store.get_value("db/password").unwrap();
    println!("password: {value}");

    let info = store.update("db/password", "n3w-s3cr3t").unwrap();
    println!("now at version {}", info.version); // version: 2

    store.delete("db/password").unwrap();
}
```

---

## API Reference

### Creating secrets

`create` fails if the key already exists. Use `set` if you want upsert behaviour.

```rust
// Create — errors if key already exists
store.create("api/key", "abc123")?;

// Upsert — creates or updates, always succeeds on valid input
store.set("api/key", "xyz789")?;
```

### Reading secrets

```rust
// Full secret entry (includes metadata)
let secret = store.get("api/key")?;
println!("id:      {}", secret.metadata.id);
println!("version: {}", secret.metadata.version);
println!("value:   {}", secret.value);

// Just the value
let value = store.get_value("api/key")?;

// Check existence without fetching
if store.exists("api/key") {
    println!("key is present");
}
```

### Updating secrets

Every successful `update` or `set` increments the version counter.

```rust
let info = store.update("api/key", "new-value")?;
println!("version is now {}", info.version);
```

### Deleting secrets

```rust
let info = store.delete("api/key")?;
println!("deleted '{}' at version {}", info.key, info.version);
```

### Listing

`list` and `list_keys` never expose secret values — they return `SecretInfo`
which contains only metadata.

```rust
// All keys, sorted alphabetically
let keys: Vec<String> = store.list_keys();

// Full metadata for all secrets (no values)
for info in store.list() {
    println!("{} — version {}, updated {}", info.key, info.version, info.updated_at);
}
```

### Tagging

Tags are arbitrary string key/value pairs attached to a secret's metadata.
Useful for environment labels, ownership, rotation schedules, etc.

```rust
// Add tags
store.tag("db/password", "env", "production")?;
store.tag("db/password", "owner", "platform-team")?;

// Query by tag
let prod_secrets = store.find_by_tag("env", "production");
for info in prod_secrets {
    println!("{}", info.key);
}

// Remove a tag
store.untag("db/password", "owner")?;
```

---

## Key Rules

Keys must follow these rules or `SecretError::InvalidKey` is returned:

| Rule | Detail |
|------|--------|
| Not empty | `""` is rejected |
| Max length | 256 bytes |
| Allowed characters | alphanumeric, `-`, `_`, `/`, `.` |

Examples of valid keys: `db/password`, `svc.api-key`, `prod/stripe/secret_key`

---

## Error Handling

All fallible operations return `Result<T, SecretError>`. Match on the variants
to handle specific cases:

```rust
use hashicorp_keyvault::SecretError;

match store.get("some/key") {
    Ok(secret) => println!("got: {}", secret.value),

    Err(SecretError::NotFound { key }) => {
        eprintln!("key '{key}' does not exist");
    }

    Err(SecretError::InvalidKey { key, reason }) => {
        eprintln!("bad key '{key}': {reason}");
    }

    Err(e) => eprintln!("unexpected error: {e}"),
}
```

Use the classification helpers when you don't need the full variant:

```rust
let err = store.get("missing").unwrap_err();

if err.is_not_found() {
    // handle missing key
}

if err.is_validation() {
    // handle invalid key or value
}
```

### Error variants

| Variant | When it occurs |
|---------|---------------|
| `NotFound { key }` | Key does not exist in the store |
| `AlreadyExists { key }` | `create` called on an existing key |
| `InvalidKey { key, reason }` | Key fails length or character validation |
| `InvalidValue { key, reason }` | Value is empty or exceeds 1 MiB |
| `Serialization(err)` | JSON serialization failure |
| `Storage { message, source }` | Backend I/O or storage failure |

---

## Value Limits

| Rule | Detail |
|------|--------|
| Not empty | `""` is rejected |
| Max size | 1 MiB (1,048,576 bytes) |

---

## Running Tests

```bash
cargo test
```

---

## License

MIT
