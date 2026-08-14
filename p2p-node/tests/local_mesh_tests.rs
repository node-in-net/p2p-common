use nodeinnet_p2p::crypto::generate_ed25519_keypair;
use nodeinnet_p2p::{NodeInfo, P2pMessage};
use p2p_node::local_mesh;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_local_mesh_handshake_and_signaling() {
    let config = client_config::AppConfig::new("ice-commander-test");

    // 2. Generate keypairs for Node A and Node B
    let (priv_a, pub_a) = generate_ed25519_keypair();
    let (priv_b, pub_b) = generate_ed25519_keypair();

    let id_a = "node_a_id";
    let id_b = "node_b_id";

    // 3. Register public keys in common's global state
    let node_a_info = NodeInfo {
        id: id_a.to_string(),
        name: "Node A".to_string(),
        os: "linux".to_string(),
        version: "0.1.0".to_string(),
        app_type: "desktop".to_string(),
        build_type: "debug".to_string(),
        public_key: pub_a.clone(),
        resources: vec![],
        is_online: true,
        last_used: 0,
        is_temporary: false,
    };
    let node_b_info = NodeInfo {
        id: id_b.to_string(),
        name: "Node B".to_string(),
        os: "linux".to_string(),
        version: "0.1.0".to_string(),
        app_type: "desktop".to_string(),
        build_type: "debug".to_string(),
        public_key: pub_b.clone(),
        resources: vec![],
        is_online: true,
        last_used: 0,
        is_temporary: false,
    };
    nodeinnet_p2p::update_known_public_keys(&[node_a_info.clone(), node_b_info.clone()]);

    // Set up local_mesh channel for Node B to receive signals
    let (signal_tx, mut signal_rx) = mpsc::channel(100);
    let _ = local_mesh::SIGNAL_TX.set(signal_tx);

    // 4. Start TCP signaling server for Node B (Responder)
    let port_b =
        local_mesh::start_tcp_signaling_server(id_b.to_string(), priv_b.clone(), config.clone())
            .await
            .expect("Failed to start responder TCP signaling server");

    // 5. Connect to B's TCP signaling server from Node A (Initiator)
    let addr_b = format!("127.0.0.1:{}", port_b);
    local_mesh::connect_to_peer_signaling(
        addr_b,
        id_b.to_string(),
        id_a.to_string(),
        priv_a.clone(),
        config.clone(),
    )
    .await
    .expect("Failed to perform Noise handshake and register tunnel");

    // 6. Verify that tunnels are successfully registered on both sides
    tokio::time::sleep(Duration::from_millis(150)).await;

    let tunnels = local_mesh::get_active_tunnels().lock().await;
    assert!(
        tunnels.contains_key(id_b),
        "Node A (Initiator) should have registered active tunnel to B"
    );

    // 7. Verify signaling over the direct Noise tunnel
    if let Some(tx) = tunnels.get(id_b) {
        let signal_msg = P2pMessage::RtcSignal {
            target_node_id: id_b.to_string(),
            signal_type: "candidate".to_string(),
            sdp_or_candidate: "candidate:12345 1 UDP 1686052863 127.0.0.1 9".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
        };
        tx.tx
            .send(signal_msg)
            .await
            .expect("Failed to send signaling message via tunnel");
    }

    // Node B (Responder) should receive this signal via its `SIGNAL_TX` channel
    let mut received_signal = None;
    for _ in 0..5 {
        let sig = tokio::time::timeout(Duration::from_secs(2), signal_rx.recv())
            .await
            .expect("Timed out waiting for signal on B")
            .expect("Signal channel closed");
        if matches!(sig, local_mesh::LocalMeshSignal::InboundRtcSignal { .. }) {
            received_signal = Some(sig);
            break;
        }
    }
    let received_signal = received_signal.expect("No InboundRtcSignal received");

    match received_signal {
        local_mesh::LocalMeshSignal::InboundRtcSignal {
            from_node_id,
            signal_type,
            sdp_or_candidate,
            sdp_mid,
            sdp_mline_index,
        } => {
            assert_eq!(from_node_id, id_a);
            assert_eq!(signal_type, "candidate");
            assert_eq!(
                sdp_or_candidate,
                "candidate:12345 1 UDP 1686052863 127.0.0.1 9"
            );
            assert_eq!(sdp_mid, Some("0".to_string()));
            assert_eq!(sdp_mline_index, Some(0));
        }
        _ => panic!("Unexpected local mesh signal"),
    }
}
