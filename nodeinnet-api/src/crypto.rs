use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

pub fn argon2_hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub fn argon2_verify_password(
    password: &str,
    hash: &str,
) -> Result<(), argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash)
}

pub fn argon2_hash_password_with_salt(
    password: &str,
    salt_b64: &str,
) -> Result<String, argon2::password_hash::Error> {
    let salt = argon2::password_hash::SaltString::from_b64(salt_b64.trim_end_matches('='))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub fn argon2_generate_salt() -> String {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    general_purpose::STANDARD_NO_PAD.encode(salt_bytes)
}

pub fn generate_ed25519_keypair() -> (String, String) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = signing_key.verifying_key();

    let priv_b64 = general_purpose::STANDARD_NO_PAD.encode(signing_key.to_bytes());
    let pub_b64 = general_purpose::STANDARD_NO_PAD.encode(verify_key.to_bytes());
    (priv_b64, pub_b64)
}

pub fn sign_p2p_handshake(
    private_key_b64: &str,
    my_id: &str,
    peer_id: &str,
    timestamp: u64,
) -> Result<String, String> {
    let priv_bytes = general_purpose::STANDARD_NO_PAD
        .decode(private_key_b64)
        .map_err(|e| e.to_string())?;
    let mut key_bytes = [0u8; 32];
    if priv_bytes.len() != 32 {
        return Err("Invalid private key length".to_string());
    }
    key_bytes.copy_from_slice(&priv_bytes);

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let payload = format!("{}:{}:{}", my_id, peer_id, timestamp);

    let signature = signing_key.sign(payload.as_bytes());
    Ok(general_purpose::STANDARD_NO_PAD.encode(signature.to_bytes()))
}

pub fn verify_p2p_handshake(
    signature_b64: &str,
    public_key_b64: &str,
    peer_id: &str,
    my_id: &str,
    timestamp: u64,
) -> Result<(), String> {
    let pub_bytes = general_purpose::STANDARD_NO_PAD
        .decode(public_key_b64)
        .map_err(|e| e.to_string())?;
    let mut key_bytes = [0u8; 32];
    if pub_bytes.len() != 32 {
        return Err("Invalid public key length".to_string());
    }
    key_bytes.copy_from_slice(&pub_bytes);

    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| e.to_string())?;

    let sig_bytes = general_purpose::STANDARD_NO_PAD
        .decode(signature_b64)
        .map_err(|e| e.to_string())?;
    let mut s_bytes = [0u8; 64];
    if sig_bytes.len() != 64 {
        return Err("Invalid signature length".to_string());
    }
    s_bytes.copy_from_slice(&sig_bytes);

    let signature = Signature::from_bytes(&s_bytes);
    let payload = format!("{}:{}:{}", peer_id, my_id, timestamp);

    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|e| e.to_string())
}

pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn compute_hmac_sha256(payload: &[u8], key_hex: &str) -> String {
    let key_bytes = hex::decode(key_hex).unwrap_or_default();
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key_bytes).expect("HMAC can take key of any size");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_hmac_sha256(payload: &[u8], key_hex: &str, expected_mac: &str) -> bool {
    let _computed = compute_hmac_sha256(payload, key_hex);
    let key_bytes = hex::decode(key_hex).unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes).unwrap();
    mac.update(payload);

    if let Ok(expected_bytes) = hex::decode(expected_mac) {
        mac.verify_slice(&expected_bytes).is_ok()
    } else {
        false
    }
}

pub fn compute_sha256(text: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(text.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

pub fn sign_message(private_key_b64: &str, message: &[u8]) -> Result<String, String> {
    let priv_bytes = general_purpose::STANDARD_NO_PAD
        .decode(private_key_b64)
        .map_err(|e| e.to_string())?;
    if priv_bytes.len() != 32 {
        return Err("Invalid private key length".to_string());
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature = signing_key.sign(message);
    Ok(general_purpose::STANDARD_NO_PAD.encode(signature.to_bytes()))
}

pub fn verify_message(
    signature_b64: &str,
    public_key_b64: &str,
    message: &[u8],
) -> Result<(), String> {
    let pub_bytes = general_purpose::STANDARD_NO_PAD
        .decode(public_key_b64)
        .map_err(|e| e.to_string())?;
    if pub_bytes.len() != 32 {
        return Err("Invalid public key length".to_string());
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&pub_bytes);
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| e.to_string())?;

    let sig_bytes = general_purpose::STANDARD_NO_PAD
        .decode(signature_b64)
        .map_err(|e| e.to_string())?;
    if sig_bytes.len() != 64 {
        return Err("Invalid signature length".to_string());
    }
    let mut s_bytes = [0u8; 64];
    s_bytes.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&s_bytes);

    verifying_key
        .verify(message, &signature)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_hash_and_verify_roundtrip() {
        let hash = argon2_hash_password("secret123").unwrap();
        assert!(argon2_verify_password("secret123", &hash).is_ok());
    }

    #[test]
    fn argon2_wrong_password_fails() {
        let hash = argon2_hash_password("correct").unwrap();
        assert!(argon2_verify_password("wrong", &hash).is_err());
    }

    #[test]
    fn argon2_same_password_different_hashes() {
        let h1 = argon2_hash_password("pass").unwrap();
        let h2 = argon2_hash_password("pass").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn argon2_with_salt_is_deterministic() {
        let salt = argon2_generate_salt();
        let h1 = argon2_hash_password_with_salt("pass", &salt).unwrap();
        let h2 = argon2_hash_password_with_salt("pass", &salt).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn argon2_generate_salt_is_valid_base64() {
        let salt = argon2_generate_salt();
        assert!(!salt.is_empty());
        assert!(general_purpose::STANDARD_NO_PAD.decode(&salt).is_ok());
    }

    #[test]
    fn generate_keypair_produces_nonempty_keys() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        assert!(!priv_key.is_empty());
        assert!(!pub_key.is_empty());
    }

    #[test]
    fn generated_keys_are_valid_base64_of_correct_length() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let priv_bytes = general_purpose::STANDARD_NO_PAD.decode(&priv_key).unwrap();
        let pub_bytes = general_purpose::STANDARD_NO_PAD.decode(&pub_key).unwrap();
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn two_keypairs_are_different() {
        let (priv1, pub1) = generate_ed25519_keypair();
        let (priv2, pub2) = generate_ed25519_keypair();
        assert_ne!(priv1, priv2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn sign_and_verify_handshake_roundtrip() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let sig = sign_p2p_handshake(&priv_key, "node_a", "node_b", 1000).unwrap();
        assert!(verify_p2p_handshake(&sig, &pub_key, "node_a", "node_b", 1000).is_ok());
    }

    #[test]
    fn handshake_fails_with_wrong_peer_id() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let sig = sign_p2p_handshake(&priv_key, "node_a", "node_b", 1000).unwrap();
        assert!(verify_p2p_handshake(&sig, &pub_key, "node_a", "node_evil", 1000).is_err());
    }

    #[test]
    fn handshake_fails_with_wrong_timestamp() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let sig = sign_p2p_handshake(&priv_key, "node_a", "node_b", 1000).unwrap();
        assert!(verify_p2p_handshake(&sig, &pub_key, "node_a", "node_b", 9999).is_err());
    }

    #[test]
    fn handshake_fails_with_wrong_public_key() {
        let (priv_key, _) = generate_ed25519_keypair();
        let (_, other_pub) = generate_ed25519_keypair();
        let sig = sign_p2p_handshake(&priv_key, "a", "b", 1).unwrap();
        assert!(verify_p2p_handshake(&sig, &other_pub, "a", "b", 1).is_err());
    }

    #[test]
    fn sign_handshake_fails_on_invalid_key() {
        assert!(sign_p2p_handshake("not_valid_base64!!!", "a", "b", 0).is_err());
    }

    #[test]
    fn session_token_is_64_hex_chars() {
        let token = generate_session_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn session_tokens_are_unique() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn hmac_known_value() {
        let key_hex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let result = compute_hmac_sha256(b"Hi There", key_hex);
        assert_eq!(
            result,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_verify_correct() {
        let key = generate_session_token();
        let mac = compute_hmac_sha256(b"payload", &key);
        assert!(verify_hmac_sha256(b"payload", &key, &mac));
    }

    #[test]
    fn hmac_verify_wrong_payload() {
        let key = generate_session_token();
        let mac = compute_hmac_sha256(b"payload", &key);
        assert!(!verify_hmac_sha256(b"tampered", &key, &mac));
    }

    #[test]
    fn hmac_verify_wrong_key() {
        let key1 = generate_session_token();
        let key2 = generate_session_token();
        let mac = compute_hmac_sha256(b"payload", &key1);
        assert!(!verify_hmac_sha256(b"payload", &key2, &mac));
    }

    #[test]
    fn sha256_known_value() {
        let result = compute_sha256("hello");
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_empty_string() {
        let result = compute_sha256("");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_different_inputs_different_hashes() {
        assert_ne!(compute_sha256("a"), compute_sha256("b"));
    }

    #[test]
    fn sign_and_verify_message_roundtrip() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let sig = sign_message(&priv_key, b"important data").unwrap();
        assert!(verify_message(&sig, &pub_key, b"important data").is_ok());
    }

    #[test]
    fn verify_message_fails_on_tampered_content() {
        let (priv_key, pub_key) = generate_ed25519_keypair();
        let sig = sign_message(&priv_key, b"original").unwrap();
        assert!(verify_message(&sig, &pub_key, b"tampered").is_err());
    }

    #[test]
    fn verify_message_fails_with_wrong_public_key() {
        let (priv_key, _) = generate_ed25519_keypair();
        let (_, other_pub) = generate_ed25519_keypair();
        let sig = sign_message(&priv_key, b"data").unwrap();
        assert!(verify_message(&sig, &other_pub, b"data").is_err());
    }

    #[test]
    fn sign_message_fails_on_invalid_key() {
        assert!(sign_message("bad_key", b"data").is_err());
    }
}
