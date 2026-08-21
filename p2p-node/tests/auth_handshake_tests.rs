use nodeinnet_p2p::crypto::{generate_ed25519_keypair, sign_p2p_handshake, verify_p2p_handshake};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_valid_auth_handshake() {
    let (priv_a, pub_a) = generate_ed25519_keypair();
    let (_, _pub_b) = generate_ed25519_keypair();

    let id_a = "node_a_123";
    let id_b = "node_b_456";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let signature =
        sign_p2p_handshake(&priv_a, id_a, id_b, timestamp).expect("Failed to sign handshake");

    let verification = verify_p2p_handshake(&signature, &pub_a, id_a, id_b, timestamp);

    assert!(
        verification.is_ok(),
        "Valid Signature & Handshake should pass verification!"
    );
}

#[test]
fn test_invalid_auth_handshake_wrong_target() {
    let (priv_a, pub_a) = generate_ed25519_keypair();
    let id_a = "node_a";
    let id_b = "node_b";
    let id_evil = "node_eve";

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let signature = sign_p2p_handshake(&priv_a, id_a, id_b, timestamp).unwrap();

    let verification = verify_p2p_handshake(&signature, &pub_a, id_evil, id_a, timestamp);

    assert!(
        verification.is_err(),
        "Handshake meant for another node must fail verification!"
    );
}

#[test]
fn test_invalid_auth_handshake_tampered_timestamp() {
    let (priv_a, pub_a) = generate_ed25519_keypair();
    let id_a = "node_a";
    let id_b = "node_b";

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let signature = sign_p2p_handshake(&priv_a, id_a, id_b, timestamp).unwrap();

    let tampered_timestamp = timestamp - 10000;
    let verification = verify_p2p_handshake(&signature, &pub_a, id_b, id_a, tampered_timestamp);

    assert!(
        verification.is_err(),
        "Tampered timestamp must break signature validity!"
    );
}
