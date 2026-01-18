//! Device code generation service for CLI authentication flow.
//!
//! This module implements the device authorization grant flow, which allows
//! CLI applications to authenticate users via a web browser. The flow works as:
//!
//! 1. CLI requests a device code
//! 2. User visits verification URL in browser
//! 3. User approves/denies the request
//! 4. CLI polls until authorized or timeout
//!
//! The word code format uses ADJ-ADJ-NOUN pattern for human-readable codes.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::seq::SliceRandom;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::device_grant::{DeviceGrant, DeviceGrantStatus};

/// Adjective word list for generating memorable word codes.
/// ~100 words covering various positive and neutral descriptors.
const ADJECTIVES: &[&str] = &[
    "white", "blue", "swift", "bright", "calm", "bold", "clear", "cool",
    "crisp", "dark", "deep", "fair", "fast", "firm", "free", "fresh",
    "glad", "gold", "good", "gray", "green", "happy", "high", "keen",
    "kind", "late", "lean", "light", "long", "loud", "mild", "neat",
    "nice", "open", "pale", "pink", "plain", "prime", "pure", "quick",
    "quiet", "rare", "rich", "ripe", "safe", "sharp", "short", "silver",
    "simple", "slim", "slow", "small", "smart", "smooth", "soft", "solid",
    "spare", "stable", "stark", "steady", "still", "strong", "sweet", "tall",
    "thick", "thin", "tight", "tiny", "true", "vast", "vivid", "warm",
    "wide", "wild", "wise", "young", "amber", "azure", "brave", "coral",
    "deft", "eager", "even", "gentle", "grand", "great", "humble", "ivory",
    "jolly", "lunar", "lucky", "mellow", "noble", "proud", "royal", "rustic",
    "serene", "sunny", "tender", "urban", "velvet", "zealous",
];

/// Noun word list for generating memorable word codes.
/// ~100 words covering nature, concepts, and objects.
const NOUNS: &[&str] = &[
    "tiger", "river", "mountain", "simplicity", "harmony", "wisdom", "forest",
    "ocean", "valley", "meadow", "sunset", "sunrise", "journey", "voyage",
    "garden", "bridge", "castle", "tower", "harbor", "island", "village",
    "prairie", "canyon", "glacier", "desert", "oasis", "summit", "horizon",
    "aurora", "comet", "nebula", "galaxy", "cosmos", "planet", "meteor",
    "crystal", "diamond", "emerald", "sapphire", "ruby", "pearl", "amber",
    "marble", "granite", "basalt", "quartz", "obsidian", "copper", "silver",
    "falcon", "eagle", "hawk", "raven", "sparrow", "phoenix", "dolphin",
    "whale", "otter", "badger", "fox", "wolf", "bear", "deer", "elk",
    "maple", "cedar", "oak", "pine", "willow", "birch", "cypress", "sequoia",
    "thunder", "lightning", "breeze", "tempest", "monsoon", "zephyr", "spirit",
    "vision", "dream", "quest", "legacy", "destiny", "fortune", "treasure",
    "compass", "anchor", "beacon", "lantern", "mirror", "prism", "mosaic",
    "tapestry", "anthem", "melody", "rhythm", "chorus", "symphony", "sonata",
    "clarity", "serenity",
];

/// Result of creating a new device grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceGrantCreated {
    /// Device code for CLI polling
    pub device_code: String,
    /// Word code for user verification
    pub word_code: String,
    /// Full verification URL
    pub verification_url: String,
    /// When the grant expires
    pub expires_at: DateTime<Utc>,
}

/// Data encoded in the verification URL parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationData {
    /// The word code for verification
    pub word_code: String,
    /// The hostname of the requesting device
    pub hostname: String,
}

/// Generates a cryptographically secure device code (64 hex characters).
///
/// The device code is used by the CLI to poll for authorization status.
/// It should never be shown to users.
///
/// # Returns
///
/// A 64-character hex string (32 bytes of random data, hex encoded).
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::device::generate_device_code;
///
/// let code = generate_device_code();
/// assert_eq!(code.len(), 64);
/// assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
/// ```
pub fn generate_device_code() -> String {
    let mut random_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);
    hex::encode(random_bytes)
}

/// Generates a human-readable word code in ADJ-ADJ-NOUN format.
///
/// Uses cryptographically secure random selection from word lists.
/// Provides approximately 1 million combinations (100 x 100 x 100).
///
/// # Returns
///
/// A string in the format "word-word-word" (lowercase, hyphen-separated).
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::device::generate_word_code;
///
/// let code = generate_word_code();
/// let parts: Vec<&str> = code.split('-').collect();
/// assert_eq!(parts.len(), 3);
/// ```
pub fn generate_word_code() -> String {
    let mut rng = rand::rngs::OsRng;

    let adj1 = ADJECTIVES
        .choose(&mut rng)
        .expect("ADJECTIVES list should not be empty");
    let adj2 = ADJECTIVES
        .choose(&mut rng)
        .expect("ADJECTIVES list should not be empty");
    let noun = NOUNS
        .choose(&mut rng)
        .expect("NOUNS list should not be empty");

    format!("{}-{}-{}", adj1, adj2, noun)
}

/// Encodes verification data into a URL-safe base64 parameter.
///
/// The encoded data contains both the word code and hostname,
/// allowing the verification page to display device information.
///
/// # Arguments
///
/// * `base_url` - The base verification URL (e.g., "https://app.spoq.dev/verify")
/// * `word_code` - The human-readable word code
/// * `hostname` - The hostname of the requesting device
///
/// # Returns
///
/// A full verification URL with the `?d=` parameter containing encoded data.
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::device::encode_verification_url;
///
/// let url = encode_verification_url(
///     "https://app.spoq.dev/verify",
///     "swift-bright-tiger",
///     "my-macbook"
/// );
/// assert!(url.starts_with("https://app.spoq.dev/verify?d="));
/// ```
pub fn encode_verification_url(base_url: &str, word_code: &str, hostname: &str) -> String {
    let data = VerificationData {
        word_code: word_code.to_string(),
        hostname: hostname.to_string(),
    };
    let json = serde_json::to_string(&data).expect("VerificationData should serialize");
    let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
    format!("{}?d={}", base_url, encoded)
}

/// Decodes the verification URL parameter back into word code and hostname.
///
/// # Arguments
///
/// * `d` - The base64-encoded `d` parameter from the verification URL
///
/// # Returns
///
/// A Result containing the decoded `VerificationData`, or an error if decoding fails.
///
/// # Example
///
/// ```
/// use spoq_web_apis::services::device::{encode_verification_url, decode_verification_param};
///
/// let url = encode_verification_url("https://example.com", "swift-bright-tiger", "my-laptop");
/// let d_param = url.split("?d=").nth(1).unwrap();
/// let data = decode_verification_param(d_param).unwrap();
/// assert_eq!(data.word_code, "swift-bright-tiger");
/// assert_eq!(data.hostname, "my-laptop");
/// ```
pub fn decode_verification_param(d: &str) -> Result<VerificationData, DecodeError> {
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|_| DecodeError::InvalidBase64)?;
    let json_str =
        String::from_utf8(decoded_bytes).map_err(|_| DecodeError::InvalidUtf8)?;
    serde_json::from_str(&json_str).map_err(|_| DecodeError::InvalidJson)
}

/// Errors that can occur when decoding verification parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The base64 encoding is invalid
    InvalidBase64,
    /// The decoded bytes are not valid UTF-8
    InvalidUtf8,
    /// The decoded JSON is malformed
    InvalidJson,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            DecodeError::InvalidUtf8 => write!(f, "Invalid UTF-8 encoding"),
            DecodeError::InvalidJson => write!(f, "Invalid JSON format"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Creates a new device grant in the database.
///
/// Generates both device code and word code, inserts into database,
/// and returns the codes needed for the auth flow.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `hostname` - The hostname of the device requesting authorization
/// * `verification_base_url` - The base URL for verification (e.g., "https://app.spoq.dev/verify")
/// * `expires_in_secs` - Seconds until the grant expires (typically 300-900)
///
/// # Returns
///
/// A Result containing `DeviceGrantCreated` with the device code, word code, and verification URL.
///
/// # Example
///
/// ```ignore
/// let grant = create_device_grant(
///     &pool,
///     "my-macbook",
///     "https://app.spoq.dev/verify",
///     300
/// ).await?;
/// println!("Device code: {}", grant.device_code);
/// println!("Verification URL: {}", grant.verification_url);
/// ```
pub async fn create_device_grant(
    pool: &PgPool,
    hostname: &str,
    verification_base_url: &str,
    expires_in_secs: i64,
) -> Result<DeviceGrantCreated, sqlx::Error> {
    let device_code = generate_device_code();
    let word_code = generate_word_code();
    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in_secs);
    let verification_url = encode_verification_url(verification_base_url, &word_code, hostname);

    sqlx::query(
        r#"
        INSERT INTO device_grants (device_code, word_code, hostname, status, expires_at)
        VALUES ($1, $2, $3, 'pending', $4)
        "#,
    )
    .bind(&device_code)
    .bind(&word_code)
    .bind(hostname)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(DeviceGrantCreated {
        device_code,
        word_code,
        verification_url,
        expires_at,
    })
}

/// Retrieves a device grant by its device code.
///
/// Used by the CLI to poll for authorization status.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `device_code` - The 64-character hex device code
///
/// # Returns
///
/// A Result containing an Option<DeviceGrant> - Some if found, None if not.
///
/// # Example
///
/// ```ignore
/// let grant = get_device_grant_by_device_code(&pool, "abc123...").await?;
/// if let Some(g) = grant {
///     match g.status {
///         DeviceGrantStatus::Approved => println!("Approved!"),
///         DeviceGrantStatus::Pending => println!("Still waiting..."),
///         _ => println!("Denied"),
///     }
/// }
/// ```
pub async fn get_device_grant_by_device_code(
    pool: &PgPool,
    device_code: &str,
) -> Result<Option<DeviceGrant>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT id, device_code, word_code, hostname, status, user_id, expires_at, created_at
        FROM device_grants
        WHERE device_code = $1
        "#,
    )
    .bind(device_code)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| {
        let status_str: String = r.get("status");
        let status = match status_str.as_str() {
            "approved" => DeviceGrantStatus::Approved,
            "denied" => DeviceGrantStatus::Denied,
            _ => DeviceGrantStatus::Pending,
        };
        DeviceGrant {
            id: r.get("id"),
            device_code: r.get("device_code"),
            word_code: r.get("word_code"),
            hostname: r.get("hostname"),
            status,
            user_id: r.get("user_id"),
            expires_at: r.get("expires_at"),
            created_at: r.get("created_at"),
        }
    }))
}

/// Retrieves a device grant by its word code.
///
/// Used by the verification page to display grant information.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `word_code` - The human-readable word code (ADJ-ADJ-NOUN format)
///
/// # Returns
///
/// A Result containing an Option<DeviceGrant> - Some if found, None if not.
///
/// # Example
///
/// ```ignore
/// let grant = get_device_grant_by_word_code(&pool, "swift-bright-tiger").await?;
/// if let Some(g) = grant {
///     println!("Device: {}", g.hostname);
/// }
/// ```
pub async fn get_device_grant_by_word_code(
    pool: &PgPool,
    word_code: &str,
) -> Result<Option<DeviceGrant>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT id, device_code, word_code, hostname, status, user_id, expires_at, created_at
        FROM device_grants
        WHERE word_code = $1
        "#,
    )
    .bind(word_code)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| {
        let status_str: String = r.get("status");
        let status = match status_str.as_str() {
            "approved" => DeviceGrantStatus::Approved,
            "denied" => DeviceGrantStatus::Denied,
            _ => DeviceGrantStatus::Pending,
        };
        DeviceGrant {
            id: r.get("id"),
            device_code: r.get("device_code"),
            word_code: r.get("word_code"),
            hostname: r.get("hostname"),
            status,
            user_id: r.get("user_id"),
            expires_at: r.get("expires_at"),
            created_at: r.get("created_at"),
        }
    }))
}

/// Approves a device grant request.
///
/// Sets the status to "approved" and associates the grant with a user.
/// Only pending grants can be approved.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `word_code` - The word code of the grant to approve
/// * `user_id` - The UUID of the user approving the grant
///
/// # Returns
///
/// A Result indicating success (true if updated, false if not found or not pending).
///
/// # Example
///
/// ```ignore
/// let approved = approve_device_grant(&pool, "swift-bright-tiger", user_id).await?;
/// if approved {
///     println!("Grant approved!");
/// }
/// ```
pub async fn approve_device_grant(
    pool: &PgPool,
    word_code: &str,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE device_grants
        SET status = 'approved', user_id = $1
        WHERE word_code = $2
          AND status = 'pending'
          AND expires_at > NOW()
        "#,
    )
    .bind(user_id)
    .bind(word_code)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Denies a device grant request.
///
/// Sets the status to "denied". Only pending grants can be denied.
///
/// # Arguments
///
/// * `pool` - The database connection pool
/// * `word_code` - The word code of the grant to deny
///
/// # Returns
///
/// A Result indicating success (true if updated, false if not found or not pending).
///
/// # Example
///
/// ```ignore
/// let denied = deny_device_grant(&pool, "swift-bright-tiger").await?;
/// if denied {
///     println!("Grant denied!");
/// }
/// ```
pub async fn deny_device_grant(pool: &PgPool, word_code: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE device_grants
        SET status = 'denied'
        WHERE word_code = $1
          AND status = 'pending'
        "#,
    )
    .bind(word_code)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Marks expired device grants as denied.
///
/// This should be called periodically to clean up expired grants.
/// Grants past their expiration time with status "pending" are updated to "denied".
///
/// # Arguments
///
/// * `pool` - The database connection pool
///
/// # Returns
///
/// A Result containing the number of grants marked as denied.
///
/// # Example
///
/// ```ignore
/// let count = expire_device_grants(&pool).await?;
/// println!("Marked {} grants as denied (expired)", count);
/// ```
pub async fn expire_device_grants(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE device_grants
        SET status = 'denied'
        WHERE status = 'pending'
          AND expires_at <= NOW()
        "#,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_device_code_length() {
        let code = generate_device_code();
        assert_eq!(code.len(), 64, "Device code should be 64 hex characters");
    }

    #[test]
    fn test_generate_device_code_hex_only() {
        let code = generate_device_code();
        assert!(
            code.chars().all(|c| c.is_ascii_hexdigit()),
            "Device code should only contain hex digits"
        );
    }

    #[test]
    fn test_generate_device_code_uniqueness() {
        let code1 = generate_device_code();
        let code2 = generate_device_code();
        assert_ne!(code1, code2, "Device codes should be unique");
    }

    #[test]
    fn test_generate_word_code_format() {
        let code = generate_word_code();
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3, "Word code should have 3 parts");
    }

    #[test]
    fn test_generate_word_code_uses_valid_words() {
        for _ in 0..100 {
            let code = generate_word_code();
            let parts: Vec<&str> = code.split('-').collect();

            assert!(
                ADJECTIVES.contains(&parts[0]),
                "First word '{}' should be a valid adjective",
                parts[0]
            );
            assert!(
                ADJECTIVES.contains(&parts[1]),
                "Second word '{}' should be a valid adjective",
                parts[1]
            );
            assert!(
                NOUNS.contains(&parts[2]),
                "Third word '{}' should be a valid noun",
                parts[2]
            );
        }
    }

    #[test]
    fn test_generate_word_code_uniqueness() {
        // Generate 100 codes and check they're mostly unique
        // (with ~1M combinations, collisions are very unlikely)
        let codes: Vec<String> = (0..100).map(|_| generate_word_code()).collect();
        let unique_count = codes
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(
            unique_count >= 95,
            "Should have at least 95 unique codes out of 100"
        );
    }

    #[test]
    fn test_encode_verification_url() {
        let url = encode_verification_url(
            "https://app.spoq.dev/verify",
            "swift-bright-tiger",
            "my-macbook",
        );
        assert!(url.starts_with("https://app.spoq.dev/verify?d="));
        assert!(!url.contains(' '), "URL should not contain spaces");
    }

    #[test]
    fn test_decode_verification_param_roundtrip() {
        let word_code = "swift-bright-tiger";
        let hostname = "my-macbook";

        let url = encode_verification_url("https://example.com", word_code, hostname);
        let d_param = url.split("?d=").nth(1).expect("URL should have d param");

        let decoded = decode_verification_param(d_param).expect("Should decode successfully");
        assert_eq!(decoded.word_code, word_code);
        assert_eq!(decoded.hostname, hostname);
    }

    #[test]
    fn test_decode_verification_param_with_special_chars() {
        let word_code = "calm-deep-harmony";
        let hostname = "john's-laptop";

        let url = encode_verification_url("https://example.com", word_code, hostname);
        let d_param = url.split("?d=").nth(1).expect("URL should have d param");

        let decoded = decode_verification_param(d_param).expect("Should decode successfully");
        assert_eq!(decoded.word_code, word_code);
        assert_eq!(decoded.hostname, hostname);
    }

    #[test]
    fn test_decode_verification_param_invalid_base64() {
        let result = decode_verification_param("!!!invalid!!!");
        assert_eq!(result, Err(DecodeError::InvalidBase64));
    }

    #[test]
    fn test_decode_verification_param_invalid_json() {
        // Valid base64 but not JSON
        let invalid = URL_SAFE_NO_PAD.encode(b"not json");
        let result = decode_verification_param(&invalid);
        assert_eq!(result, Err(DecodeError::InvalidJson));
    }

    #[test]
    fn test_adjectives_list_size() {
        assert!(
            ADJECTIVES.len() >= 100,
            "Should have at least 100 adjectives, got {}",
            ADJECTIVES.len()
        );
    }

    #[test]
    fn test_nouns_list_size() {
        assert!(
            NOUNS.len() >= 100,
            "Should have at least 100 nouns, got {}",
            NOUNS.len()
        );
    }

    #[test]
    fn test_word_lists_all_lowercase() {
        for adj in ADJECTIVES {
            assert!(
                adj.chars().all(|c| c.is_lowercase()),
                "Adjective '{}' should be lowercase",
                adj
            );
        }
        for noun in NOUNS {
            assert!(
                noun.chars().all(|c| c.is_lowercase()),
                "Noun '{}' should be lowercase",
                noun
            );
        }
    }

    #[test]
    fn test_decode_error_display() {
        assert_eq!(
            format!("{}", DecodeError::InvalidBase64),
            "Invalid base64 encoding"
        );
        assert_eq!(
            format!("{}", DecodeError::InvalidUtf8),
            "Invalid UTF-8 encoding"
        );
        assert_eq!(
            format!("{}", DecodeError::InvalidJson),
            "Invalid JSON format"
        );
    }

    #[test]
    fn test_verification_data_serialization() {
        let data = VerificationData {
            word_code: "test-word-code".to_string(),
            hostname: "test-host".to_string(),
        };

        let json = serde_json::to_string(&data).expect("Should serialize");
        assert!(json.contains("word_code"));
        assert!(json.contains("hostname"));

        let parsed: VerificationData =
            serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(parsed.word_code, data.word_code);
        assert_eq!(parsed.hostname, data.hostname);
    }

    #[test]
    fn test_device_grant_created_serialization() {
        let grant = DeviceGrantCreated {
            device_code: "abc123".to_string(),
            word_code: "test-word-code".to_string(),
            verification_url: "https://example.com/verify?d=xyz".to_string(),
            expires_at: Utc::now(),
        };

        let json = serde_json::to_string(&grant).expect("Should serialize");
        assert!(json.contains("device_code"));
        assert!(json.contains("word_code"));
        assert!(json.contains("verification_url"));
        assert!(json.contains("expires_at"));
    }
}
