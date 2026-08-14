use nodeinnet_p2p::crypto::{generate_ed25519_keypair, sign_p2p_handshake, verify_p2p_handshake};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_valid_auth_handshake() {
    // 1. Generate keys for two peers
    let (priv_a, pub_a) = generate_ed25519_keypair();
    let (_, _pub_b) = generate_ed25519_keypair();

    let id_a = "node_a_123";
    let id_b = "node_b_456";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // 2. Peer A creates a handshake aimed at Peer B
    let signature =
        sign_p2p_handshake(&priv_a, id_a, id_b, timestamp).expect("Failed to sign handshake");

    // 3. Peer B receives handshakes and verifies using Peer A's public key
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

    // A signs payload for B
    let signature = sign_p2p_handshake(&priv_a, id_a, id_b, timestamp).unwrap();

    // Eve intercepts and tries to verify it as if it was meant for her
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

    // A signs payload with T = timestamp
    let signature = sign_p2p_handshake(&priv_a, id_a, id_b, timestamp).unwrap();

    // Eve replays the packet with an old timestamp
    let tampered_timestamp = timestamp - 10000;
    let verification = verify_p2p_handshake(&signature, &pub_a, id_b, id_a, tampered_timestamp);

    assert!(
        verification.is_err(),
        "Tampered timestamp must break signature validity!"
    );
}
