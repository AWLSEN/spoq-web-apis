use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;

/// Generate 6-character alphanumeric code (A-Z, 0-9)
/// Example: "A7B3K9"
pub fn generate_registration_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hash registration code using Argon2id (same pattern as token.rs)
pub fn hash_code(code: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(code.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify code against hash (constant-time comparison)
pub fn verify_code(code: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else { return false };
    Argon2::default().verify_password(code.as_bytes(), &parsed).is_ok()
}

/// Generate VPS secret (format: spoq_vps_{43 chars})
/// Used for ongoing Conductor → API authentication
pub fn generate_vps_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill(&mut bytes);
    format!("spoq_vps_{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_code_format() {
        let code = generate_registration_code();
        assert_eq!(code.len(), 6, "Code must be 6 characters");
        assert!(
            code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "Code must be A-Z, 0-9 only"
        );
    }

    #[test]
    fn test_registration_code_uniqueness() {
        let codes: Vec<String> = (0..100).map(|_| generate_registration_code()).collect();
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(codes.len(), unique.len(), "Codes should be unique");
    }

    #[test]
    fn test_code_hash_and_verify() {
        let code = "ABC123";
        let hash = hash_code(code).expect("Hash should succeed");
        assert!(verify_code(code, &hash), "Valid code should verify");
        assert!(!verify_code("WRONG1", &hash), "Wrong code should not verify");
        assert!(!verify_code("abc123", &hash), "Lowercase should not verify");
    }

    #[test]
    fn test_vps_secret_format() {
        let secret = generate_vps_secret();
        assert!(secret.starts_with("spoq_vps_"), "Secret must have prefix");
        assert_eq!(secret.len(), 52, "Secret must be 52 chars (9 prefix + 43 base64)");
    }
}
