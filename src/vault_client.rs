//! HTTP client for communicating with HashiCorp Vault servers.

use std::time::Duration;
use serde_json::{json, Value};
use std::collections::HashSet;
use crate::error::{Result, SecretError};

const LOG_BODY_PREVIEW_LEN: usize = 300;

fn preview(s: &str, max_len: usize) -> String {
    s.chars().take(max_len).collect::<String>()
}

fn build_vault_api_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim();

    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }

    let normalized_path = path.trim_start_matches('/');
    if normalized_path.starts_with("v1/") {
        format!("{}/{}", base, normalized_path)
    } else if base.ends_with("/v1") {
        format!("{}/{}", base, normalized_path)
    } else {
        format!("{}/v1/{}", base, normalized_path)
    }
}

fn build_login_path(approle_mount_path: Option<&str>) -> String {
    approle_mount_path
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| {
            let trimmed = v.trim_start_matches('/').trim_end_matches('/');
            if trimmed.starts_with("auth/") {
                format!("{}/login", trimmed)
            } else {
                format!("auth/{}/login", trimmed)
            }
        })
        .unwrap_or_else(|| "auth/approle/login".to_string())
}

fn build_candidate_paths(bucket_path: &str) -> Vec<String> {
    let raw_path = bucket_path.trim().trim_start_matches('/');
    let mut candidate_paths: Vec<String> = Vec::new();

    if let Some(slash_pos) = raw_path.find('/') {
        let mount = &raw_path[..slash_pos];
        let rest = &raw_path[slash_pos + 1..];
        candidate_paths.push(format!("{}/data/{}", mount, rest));
    }

    candidate_paths.push(raw_path.to_string());

    if raw_path.starts_with("v1/") {
        candidate_paths.push(raw_path.trim_start_matches("v1/").to_string());
    }

    if raw_path.contains("/data/") {
        candidate_paths.push(raw_path.replacen("/data/", "/", 1));
    }

    let mut seen = HashSet::new();
    candidate_paths.retain(|p| seen.insert(p.clone()));
    candidate_paths
}

/// HTTP client for Vault.
pub struct VaultClient {
    http: reqwest::Client,
    base_url: String,
}

impl VaultClient {
    /// Create a new Vault HTTP client.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| SecretError::storage(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            http,
            base_url: base_url.into(),
        })
    }

    /// Authenticate with AppRole and return the client token.
    pub async fn login_with_approle(
        &self,
        role_id: &str,
        secret_id: &str,
        mount_path: Option<&str>,
    ) -> Result<String> {
        let login_path = build_login_path(mount_path);
        let login_url = build_vault_api_url(&self.base_url, &login_path);

        tracing::info!(login_url = %login_url, "Calling Vault AppRole login");
        
        let login_resp = self
            .http
            .post(&login_url)
            .json(&json!({ "role_id": role_id, "secret_id": secret_id }))
            .send()
            .await
            .map_err(|e| SecretError::storage(format!("Failed to call Vault AppRole login API: {}", e)))?;

        if !login_resp.status().is_success() {
            let status = login_resp.status();
            let body = login_resp.text().await.unwrap_or_default();
            tracing::warn!(
                login_url = %login_url,
                status = %status,
                body_preview = %preview(&body, 500),
                "Vault AppRole login failed"
            );
            return Err(SecretError::storage(format!(
                "Vault AppRole login failed ({}): {}",
                status,
                preview(&body, LOG_BODY_PREVIEW_LEN)
            )));
        }

        let login_json: Value = login_resp
            .json()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "Invalid AppRole login JSON");
                SecretError::storage(format!("Invalid Vault AppRole login JSON: {}", e))
            })?;

        tracing::debug!("Vault AppRole login succeeded");
        login_json
            .get("auth")
            .and_then(|a| a.get("client_token"))
            .and_then(Value::as_str)
            .map(|t| t.to_string())
            .ok_or_else(|| SecretError::storage("Vault AppRole login response missing auth.client_token"))
    }

    /// Fetch a secret value from Vault using fallback paths.
    pub async fn fetch_secret_value(
        &self,
        token: &str,
        bucket_path: &str,
        key: &str,
    ) -> Result<String> {
        let candidate_paths = build_candidate_paths(bucket_path);
        tracing::debug!(candidate_paths = ?candidate_paths, "Vault candidate paths built");

        let mut secret_body: Option<Value> = None;
        let mut last_error = String::new();
        let mut permission_denied_errors: Vec<String> = Vec::new();
        let mut attempted_errors: Vec<String> = Vec::new();

        for candidate in candidate_paths {
            let secret_url = build_vault_api_url(&self.base_url, &candidate);

            let secret_resp = self
                .http
                .get(&secret_url)
                .header("X-Vault-Token", token)
                .send()
                .await
                .map_err(|e| SecretError::storage(format!("Failed to call Vault secret API: {}", e)))?;

            if !secret_resp.status().is_success() {
                let status = secret_resp.status();
                let body = secret_resp.text().await.unwrap_or_default();
                last_error = format!(
                    "url={} status={} body={}",
                    secret_url,
                    status,
                    preview(&body, LOG_BODY_PREVIEW_LEN)
                );
                attempted_errors.push(last_error.clone());
                tracing::warn!(error = %last_error, "Vault secret read failed for candidate path");
                if status == reqwest::StatusCode::FORBIDDEN {
                    permission_denied_errors.push(last_error.clone());
                }
                continue;
            }

            let body: Value = secret_resp
                .json()
                .await
                .map_err(|e| {
                    tracing::warn!(secret_url = %secret_url, error = %e, "Invalid Vault secret JSON response");
                    SecretError::storage(format!("Invalid Vault secret JSON response: {}", e))
                })?;
            secret_body = Some(body);
            tracing::debug!(secret_url = %secret_url, "Vault secret read succeeded");
            break;
        }

        let body = secret_body.ok_or_else(|| {
            if !permission_denied_errors.is_empty() {
                return SecretError::storage(format!(
                    "Vault permission denied. key='{}' bucketPath='{}'. attempted_paths=[{}]. denied_paths=[{}]",
                    key,
                    bucket_path,
                    attempted_errors.join(" | "),
                    permission_denied_errors.join(" | ")
                ));
            }
            SecretError::storage(format!(
                "Vault secret read failed. key='{}' bucketPath='{}'. attempted_paths=[{}]. last_error={}",
                key,
                bucket_path,
                attempted_errors.join(" | "),
                last_error
            ))
        })?;

        // Support KV v1 (data.key) and KV v2 (data.data.key)
        let direct = body
            .get("data")
            .and_then(|d| d.get(key))
            .and_then(Value::as_str);
        let kv_v2 = body
            .get("data")
            .and_then(|d| d.get("data"))
            .and_then(|d| d.get(key))
            .and_then(Value::as_str);

        direct
            .or(kv_v2)
            .map(|v| v.to_string())
            .ok_or_else(|| {
                tracing::warn!(
                    key = %key,
                    bucket_path = %bucket_path,
                    response_preview = %preview(&body.to_string(), 500),
                    "Vault key not found in successful secret response"
                );
                SecretError::not_found(format!("Vault key '{}' not found at '{}'", key, bucket_path))
            })
    }
}
