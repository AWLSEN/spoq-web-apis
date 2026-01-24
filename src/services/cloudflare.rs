use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct CloudflareService {
    client: Client,
    api_token: String,
    zone_id: String,
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

#[derive(Debug, thiserror::Error)]
pub enum CloudflareServiceError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("Cloudflare API error: {0}")]
    ApiError(String),
    #[error("DNS record not found")]
    RecordNotFound,
}

impl CloudflareService {
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
        }
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
}
