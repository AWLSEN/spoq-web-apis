use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct CloudflareService {
    client: Client,
    api_token: String,
    zone_id: String,
    account_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateDnsRecordRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
    proxied: bool,
}

#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CloudflareError {
    code: i32,
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
}

/// Credentials returned when creating a Cloudflare Tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelCredentials {
    pub tunnel_id: String,
    pub tunnel_secret: String,
    pub account_tag: String,
    pub tunnel_name: String,
}

/// Response from Cloudflare Tunnel API
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TunnelResult {
    id: String,
    name: String,
    account_tag: String,
    created_at: Option<String>,
    deleted_at: Option<String>,
}

/// Request body for creating a tunnel
#[derive(Debug, Serialize)]
struct CreateTunnelRequest {
    name: String,
    tunnel_secret: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CloudflareServiceError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("Cloudflare API error: {0}")]
    ApiError(String),
    #[error("DNS record not found")]
    RecordNotFound,
    #[error("Tunnel not found")]
    TunnelNotFound,
    #[error("Account ID not configured")]
    AccountIdNotConfigured,
}

impl CloudflareService {
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
            account_id: None,
        }
    }

    /// Create a CloudflareService with account ID for tunnel operations
    pub fn with_account_id(api_token: String, zone_id: String, account_id: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
            account_id: Some(account_id),
        }
    }

    /// Set the account ID for tunnel operations
    pub fn set_account_id(&mut self, account_id: String) {
        self.account_id = Some(account_id);
    }

    /// Create an A record: {subdomain}.spoq.dev -> ip_address
    pub async fn create_dns_record(
        &self,
        subdomain: &str,
        ip_address: &str,
    ) -> Result<DnsRecord, CloudflareServiceError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        let request = CreateDnsRecordRequest {
            record_type: "A".to_string(),
            name: subdomain.to_string(),
            content: ip_address.to_string(),
            ttl: 1, // Auto
            proxied: false, // Direct connection for Conductor
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let cf_response: CloudflareResponse<DnsRecord> = response.json().await?;

        if cf_response.success {
            cf_response.result.ok_or(CloudflareServiceError::ApiError(
                "No result in response".to_string(),
            ))
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }

    /// Delete a DNS record by subdomain
    pub async fn delete_dns_record(
        &self,
        subdomain: &str,
    ) -> Result<(), CloudflareServiceError> {
        // First, find the record
        let record = self.find_dns_record(subdomain).await?;

        // Then delete it
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.zone_id, record.id
        );

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        let cf_response: CloudflareResponse<serde_json::Value> = response.json().await?;

        if cf_response.success {
            Ok(())
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }

    /// Find a DNS record by subdomain
    pub async fn find_dns_record(
        &self,
        subdomain: &str,
    ) -> Result<DnsRecord, CloudflareServiceError> {
        let full_name = if subdomain.ends_with(".spoq.dev") {
            subdomain.to_string()
        } else {
            format!("{}.spoq.dev", subdomain)
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=A&name={}",
            self.zone_id, full_name
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        let cf_response: CloudflareResponse<Vec<DnsRecord>> = response.json().await?;

        if cf_response.success {
            cf_response
                .result
                .and_then(|records| records.into_iter().next())
                .ok_or(CloudflareServiceError::RecordNotFound)
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }

    /// Update an existing DNS record
    pub async fn update_dns_record(
        &self,
        subdomain: &str,
        new_ip: &str,
    ) -> Result<DnsRecord, CloudflareServiceError> {
        // First try to find existing record
        match self.find_dns_record(subdomain).await {
            Ok(record) => {
                // Update existing
                let url = format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                    self.zone_id, record.id
                );

                let request = CreateDnsRecordRequest {
                    record_type: "A".to_string(),
                    name: subdomain.to_string(),
                    content: new_ip.to_string(),
                    ttl: 1,
                    proxied: false,
                };

                let response = self
                    .client
                    .put(&url)
                    .header("Authorization", format!("Bearer {}", self.api_token))
                    .header("Content-Type", "application/json")
                    .json(&request)
                    .send()
                    .await?;

                let cf_response: CloudflareResponse<DnsRecord> = response.json().await?;

                if cf_response.success {
                    cf_response.result.ok_or(CloudflareServiceError::ApiError(
                        "No result in response".to_string(),
                    ))
                } else {
                    let error_msg = cf_response
                        .errors
                        .first()
                        .map(|e| e.message.clone())
                        .unwrap_or_else(|| "Unknown error".to_string());
                    Err(CloudflareServiceError::ApiError(error_msg))
                }
            }
            Err(CloudflareServiceError::RecordNotFound) => {
                // Create new
                self.create_dns_record(subdomain, new_ip).await
            }
            Err(e) => Err(e),
        }
    }

    /// Create a wildcard A record: *.{subdomain}.spoq.dev -> ip_address
    pub async fn create_wildcard_dns_record(
        &self,
        subdomain: &str,
        ip_address: &str,
    ) -> Result<DnsRecord, CloudflareServiceError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        let wildcard_name = format!("*.{}", subdomain);

        let request = CreateDnsRecordRequest {
            record_type: "A".to_string(),
            name: wildcard_name,
            content: ip_address.to_string(),
            ttl: 1, // Auto
            proxied: false, // Direct connection for Conductor
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let cf_response: CloudflareResponse<DnsRecord> = response.json().await?;

        if cf_response.success {
            cf_response.result.ok_or(CloudflareServiceError::ApiError(
                "No result in response".to_string(),
            ))
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }

    /// Find a wildcard DNS record by subdomain
    pub async fn find_wildcard_dns_record(
        &self,
        subdomain: &str,
    ) -> Result<DnsRecord, CloudflareServiceError> {
        let full_name = if subdomain.starts_with("*.") {
            if subdomain.ends_with(".spoq.dev") {
                subdomain.to_string()
            } else {
                format!("{}.spoq.dev", subdomain)
            }
        } else if subdomain.ends_with(".spoq.dev") {
            format!("*.{}", subdomain)
        } else {
            format!("*.{}.spoq.dev", subdomain)
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=A&name={}",
            self.zone_id, full_name
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        let cf_response: CloudflareResponse<Vec<DnsRecord>> = response.json().await?;

        if cf_response.success {
            cf_response
                .result
                .and_then(|records| records.into_iter().next())
                .ok_or(CloudflareServiceError::RecordNotFound)
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }

    /// Update an existing wildcard DNS record (upsert pattern)
    pub async fn update_wildcard_dns_record(
        &self,
        subdomain: &str,
        new_ip: &str,
    ) -> Result<DnsRecord, CloudflareServiceError> {
        // First try to find existing record
        match self.find_wildcard_dns_record(subdomain).await {
            Ok(record) => {
                // Update existing
                let url = format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                    self.zone_id, record.id
                );

                let wildcard_name = format!("*.{}", subdomain);

                let request = CreateDnsRecordRequest {
                    record_type: "A".to_string(),
                    name: wildcard_name,
                    content: new_ip.to_string(),
                    ttl: 1,
                    proxied: false,
                };

                let response = self
                    .client
                    .put(&url)
                    .header("Authorization", format!("Bearer {}", self.api_token))
                    .header("Content-Type", "application/json")
                    .json(&request)
                    .send()
                    .await?;

                let cf_response: CloudflareResponse<DnsRecord> = response.json().await?;

                if cf_response.success {
                    cf_response.result.ok_or(CloudflareServiceError::ApiError(
                        "No result in response".to_string(),
                    ))
                } else {
                    let error_msg = cf_response
                        .errors
                        .first()
                        .map(|e| e.message.clone())
                        .unwrap_or_else(|| "Unknown error".to_string());
                    Err(CloudflareServiceError::ApiError(error_msg))
                }
            }
            Err(CloudflareServiceError::RecordNotFound) => {
                // Create new
                self.create_wildcard_dns_record(subdomain, new_ip).await
            }
            Err(e) => Err(e),
        }
    }

    // ============================================
    // Cloudflare Tunnel Methods
    // ============================================

    /// Create a new Cloudflare Tunnel
    /// Returns tunnel credentials including the generated secret
    pub async fn create_tunnel(
        &self,
        name: &str,
    ) -> Result<TunnelCredentials, CloudflareServiceError> {
        let account_id = self
            .account_id
            .as_ref()
            .ok_or(CloudflareServiceError::AccountIdNotConfigured)?;

        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel",
            account_id
        );

        // Generate a 32-byte random secret and base64 encode it
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let tunnel_secret = BASE64_STANDARD.encode(secret_bytes);

        let request = CreateTunnelRequest {
            name: name.to_string(),
            tunnel_secret: tunnel_secret.clone(),
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let cf_response: CloudflareResponse<TunnelResult> = response.json().await?;

        if cf_response.success {
            let result = cf_response.result.ok_or(CloudflareServiceError::ApiError(
                "No result in response".to_string(),
            ))?;

            Ok(TunnelCredentials {
                tunnel_id: result.id,
                tunnel_secret,
                account_tag: result.account_tag,
                tunnel_name: result.name,
            })
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }

    /// Delete a Cloudflare Tunnel by ID
    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<(), CloudflareServiceError> {
        let account_id = self
            .account_id
            .as_ref()
            .ok_or(CloudflareServiceError::AccountIdNotConfigured)?;

        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/cfd_tunnel/{}",
            account_id, tunnel_id
        );

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        let cf_response: CloudflareResponse<serde_json::Value> = response.json().await?;

        if cf_response.success {
            Ok(())
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());

            // Check if tunnel not found
            if error_msg.contains("not found") || error_msg.contains("does not exist") {
                Err(CloudflareServiceError::TunnelNotFound)
            } else {
                Err(CloudflareServiceError::ApiError(error_msg))
            }
        }
    }

    /// Create a CNAME record pointing to a Cloudflare Tunnel
    /// The CNAME content will be {tunnel_id}.cfargotunnel.com with proxied: true
    pub async fn create_cname_record(
        &self,
        name: &str,
        tunnel_id: &str,
    ) -> Result<DnsRecord, CloudflareServiceError> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        let tunnel_target = format!("{}.cfargotunnel.com", tunnel_id);

        let request = CreateDnsRecordRequest {
            record_type: "CNAME".to_string(),
            name: name.to_string(),
            content: tunnel_target,
            ttl: 1, // Auto
            proxied: true, // Tunnel CNAMEs must be proxied
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let cf_response: CloudflareResponse<DnsRecord> = response.json().await?;

        if cf_response.success {
            cf_response.result.ok_or(CloudflareServiceError::ApiError(
                "No result in response".to_string(),
            ))
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }

    /// Find a CNAME DNS record by subdomain
    pub async fn find_cname_record(
        &self,
        subdomain: &str,
    ) -> Result<DnsRecord, CloudflareServiceError> {
        let full_name = if subdomain.ends_with(".spoq.dev") {
            subdomain.to_string()
        } else {
            format!("{}.spoq.dev", subdomain)
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=CNAME&name={}",
            self.zone_id, full_name
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        let cf_response: CloudflareResponse<Vec<DnsRecord>> = response.json().await?;

        if cf_response.success {
            cf_response
                .result
                .and_then(|records| records.into_iter().next())
                .ok_or(CloudflareServiceError::RecordNotFound)
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }

    /// Delete a CNAME record by subdomain
    pub async fn delete_cname_record(&self, subdomain: &str) -> Result<(), CloudflareServiceError> {
        // First, find the record
        let record = self.find_cname_record(subdomain).await?;

        // Then delete it
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.zone_id, record.id
        );

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        let cf_response: CloudflareResponse<serde_json::Value> = response.json().await?;

        if cf_response.success {
            Ok(())
        } else {
            let error_msg = cf_response
                .errors
                .first()
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(CloudflareServiceError::ApiError(error_msg))
        }
    }
}
