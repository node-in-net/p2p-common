use base64::{engine::general_purpose, Engine as _};
use nodeinnet_p2p::{NodeInfo, NodeTopologyInfo, P2pMessage};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct TunnelSession {
    pub tx: mpsc::Sender<P2pMessage>,
    pub connection_id: uuid::Uuid,
}

pub static ACTIVE_TCP_TUNNELS: OnceLock<Mutex<HashMap<String, TunnelSession>>> = OnceLock::new();
pub static LOCAL_TCP_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

#[derive(Debug, Clone)]
pub enum LocalMeshSignal {
    InboundRtcSignal {
        from_node_id: String,
        signal_type: String,
        sdp_or_candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
    PeerDiscovered(NodeInfo),
    TunnelEstablished(String),
}

pub static SIGNAL_TX: OnceLock<mpsc::Sender<LocalMeshSignal>> = OnceLock::new();

pub fn get_active_tunnels() -> &'static Mutex<HashMap<String, TunnelSession>> {
    ACTIVE_TCP_TUNNELS.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn read_packet<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Packet too large",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_packet<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), std::io::Error> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}

fn get_noise_private_key(priv_b64: &str) -> Result<[u8; 32], String> {
    let decoded = general_purpose::STANDARD_NO_PAD
        .decode(priv_b64)
        .map_err(|e| e.to_string())?;
    if decoded.len() != 32 {
        return Err("Invalid private key size".to_string());
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(&decoded);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

pub async fn start_tcp_signaling_server(
    my_id: String,
    private_key_b64: String,
    config: client_config::AppConfig,
) -> Result<u16, String> {
    let existing_port = LOCAL_TCP_PORT.load(std::sync::atomic::Ordering::Relaxed);
    if existing_port > 0 {
        return Ok(existing_port);
    }
    let addr = "0.0.0.0:8308".parse::<std::net::SocketAddr>().unwrap();
    let socket = tokio::net::TcpSocket::new_v4().map_err(|e| e.to_string())?;
    let _ = socket.set_reuseaddr(true);

    if let Err(e) = socket.bind(addr) {
        let err_msg = format!("failed to bind to port 8308: {}", e);
        return Err(err_msg);
    }
    let listener = match socket.listen(1024) {
        Ok(l) => l,
        Err(e) => {
            let err_msg = format!("failed to listen on port 8308: {}", e);
            return Err(err_msg);
        }
    };
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    LOCAL_TCP_PORT.store(port, std::sync::atomic::Ordering::Relaxed);

    let priv_key_noise = get_noise_private_key(&private_key_b64)?;

    let my_id_clone = my_id.clone();
    let config_clone = config.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let my_id = my_id_clone.clone();
                    let priv_key_noise = priv_key_noise;
                    let private_key_b64 = private_key_b64.clone();
                    let config = config_clone.clone();

                    tokio::spawn(async move {
                        let _ = handle_incoming_tcp_tunnel(
                            stream,
                            my_id,
                            priv_key_noise,
                            private_key_b64,
                            config,
                        )
                        .await;
                    });
                }
                Err(_e) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    });
    Ok(port)
}

async fn handle_incoming_tcp_tunnel(
    mut stream: TcpStream,
    my_id: String,
    priv_key_noise: [u8; 32],
    private_key_b64: String,
    config: client_config::AppConfig,
) -> Result<(), String> {
    let builder = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap());
    let mut noise = builder
        .local_private_key(&priv_key_noise)
        .build_responder()
        .map_err(|e| e.to_string())?;

    let pkt1 = read_packet(&mut stream)
        .await
        .map_err(|e| format!("failed reading Msg 1: {}", e))?;
    let mut payload = vec![0u8; 65535];
    noise
        .read_message(&pkt1, &mut payload)
        .map_err(|e| format!("failed reading Msg 1 payload: {}", e))?;

    let mut buf = vec![0u8; 65535];
    let len2 = noise
        .write_message(&[], &mut buf)
        .map_err(|e| format!("failed writing Msg 2: {}", e))?;
    write_packet(&mut stream, &buf[..len2])
        .await
        .map_err(|e| format!("failed sending Msg 2: {}", e))?;

    let pkt3 = read_packet(&mut stream)
        .await
        .map_err(|e| format!("failed reading Msg 3: {}", e))?;
    noise
        .read_message(&pkt3, &mut payload)
        .map_err(|e| format!("failed reading Msg 3 payload: {}", e))?;

    let mut session = noise.into_transport_mode().map_err(|e| e.to_string())?;

    let encrypted_hs = read_packet(&mut stream)
        .await
        .map_err(|e| format!("failed reading encrypted handshake: {}", e))?;
    let mut decrypted_hs = vec![0u8; 65535];
    let hs_len = session
        .read_message(&encrypted_hs, &mut decrypted_hs)
        .map_err(|e| format!("failed reading transport handshake payload: {}", e))?;

    let envelope: nodeinnet_p2p::SecuredP2pEnvelope =
        serde_json::from_slice(&decrypted_hs[..hs_len])
            .map_err(|e| format!("failed parsing handshake envelope: {}", e))?;

    if let P2pMessage::Handshake {
        ref signature,
        timestamp_ms,
        local_tcp_port: _,
        from_node_id: Some(ref initiator_id),
        ..
    } = envelope.message
    {
        let pub_key = nodeinnet_p2p::get_known_public_key(initiator_id).ok_or_else(|| {
            format!("No known public key for initiator {}", initiator_id)
        })?;

        nodeinnet_p2p::crypto::verify_p2p_handshake(
            signature,
            &pub_key,
            initiator_id,
            &my_id,
            timestamp_ms,
        )
        .map_err(|e| {
            format!("handshake signature verification failed: {}", e)
        })?;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let my_signature =
            nodeinnet_p2p::crypto::sign_p2p_handshake(&private_key_b64, &my_id, initiator_id, ts)?;

        let response_hs = P2pMessage::Handshake {
            node_version: crate::app_version().to_string(),
            timestamp_ms: ts,
            signature: my_signature,
            requested_resources: None,
            max_chunk_size: Some(10240),
            local_tcp_port: Some(LOCAL_TCP_PORT.load(std::sync::atomic::Ordering::Relaxed)),
            from_node_id: Some(my_id.clone()),
        };

        let response_env = nodeinnet_p2p::SecuredP2pEnvelope {
            mac: None,
            message: response_hs,
        };
        let response_bytes = serde_json::to_vec(&response_env).map_err(|e| e.to_string())?;

        let mut enc_buf = vec![0u8; 65535];
        let enc_len = session
            .write_message(&response_bytes, &mut enc_buf)
            .map_err(|e| e.to_string())?;
        write_packet(&mut stream, &enc_buf[..enc_len])
            .await
            .map_err(|e| e.to_string())?;

        let connection_id = uuid::Uuid::new_v4();
        let (tx, rx) = mpsc::channel(100);
        get_active_tunnels()
            .lock()
            .await
            .insert(initiator_id.clone(), TunnelSession { tx, connection_id });


        if let Some(sig_tx) = SIGNAL_TX.get() {
            let _ = sig_tx
                .send(LocalMeshSignal::TunnelEstablished(initiator_id.clone()))
                .await;
        }

        let initiator_id_clone = initiator_id.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            let _ = run_tunnel_loop(
                stream,
                session,
                rx,
                initiator_id_clone,
                my_id,
                connection_id,
                config_clone,
            )
            .await;
        });

        Ok(())
    } else {
        Err("Invalid Handshake message".to_string())
    }
}

pub async fn connect_to_peer_signaling(
    addr: String,
    target_node_id: String,
    my_id: String,
    private_key_b64: String,
    config: client_config::AppConfig,
) -> Result<(), String> {
    let mut stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            return Err(e.to_string());
        }
    };

    let priv_key_noise = get_noise_private_key(&private_key_b64)?;
    let builder = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap());
    let mut noise = builder
        .local_private_key(&priv_key_noise)
        .build_initiator()
        .map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 65535];
    let len1 = noise
        .write_message(&[], &mut buf)
        .map_err(|e| format!("Msg 1 write error: {}", e))?;
    write_packet(&mut stream, &buf[..len1])
        .await
        .map_err(|e| format!("Msg 1 send error: {}", e))?;

    let pkt2 = read_packet(&mut stream)
        .await
        .map_err(|e| format!("Msg 2 read error: {}", e))?;
    let mut payload = vec![0u8; 65535];
    noise
        .read_message(&pkt2, &mut payload)
        .map_err(|e| format!("Msg 2 payload error: {}", e))?;

    let len3 = noise
        .write_message(&[], &mut buf)
        .map_err(|e| format!("Msg 3 write error: {}", e))?;
    write_packet(&mut stream, &buf[..len3])
        .await
        .map_err(|e| format!("Msg 3 send error: {}", e))?;

    let mut session = noise.into_transport_mode().map_err(|e| e.to_string())?;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let signature =
        nodeinnet_p2p::crypto::sign_p2p_handshake(&private_key_b64, &my_id, &target_node_id, ts)?;

    let local_port = LOCAL_TCP_PORT.load(std::sync::atomic::Ordering::Relaxed);
    let handshake = P2pMessage::Handshake {
        node_version: crate::app_version().to_string(),
        timestamp_ms: ts,
        signature,
        requested_resources: None,
        max_chunk_size: Some(10240),
        local_tcp_port: if local_port > 0 {
            Some(local_port)
        } else {
            None
        },
        from_node_id: Some(my_id.clone()),
    };

    let envelope = nodeinnet_p2p::SecuredP2pEnvelope {
        mac: None,
        message: handshake,
    };
    let envelope_bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;

    let mut enc_buf = vec![0u8; 65535];
    let enc_len = session
        .write_message(&envelope_bytes, &mut enc_buf)
        .map_err(|e| e.to_string())?;
    write_packet(&mut stream, &enc_buf[..enc_len])
        .await
        .map_err(|e| e.to_string())?;

    let response_pkt = read_packet(&mut stream)
        .await
        .map_err(|e| format!("failed reading responder handshake: {}", e))?;
    let mut dec_buf = vec![0u8; 65535];
    let dec_len = session
        .read_message(&response_pkt, &mut dec_buf)
        .map_err(|e| format!("failed decrypting responder handshake: {}", e))?;

    let response_env: nodeinnet_p2p::SecuredP2pEnvelope =
        serde_json::from_slice(&dec_buf[..dec_len])
            .map_err(|e| format!("failed parsing responder handshake: {}", e))?;

    if let P2pMessage::Handshake {
        ref signature,
        timestamp_ms,
        local_tcp_port: _,
        from_node_id: Some(ref resp_id),
        ..
    } = response_env.message
    {
        if resp_id != &target_node_id {
            let err = format!(
                "Responder node ID mismatch: expected {}, got {}",
                target_node_id, resp_id
            );
            return Err(err);
        }

        let pub_key = nodeinnet_p2p::get_known_public_key(resp_id).ok_or_else(|| {
            let err = format!("No known public key for responder {}", resp_id);
            err
        })?;

        nodeinnet_p2p::crypto::verify_p2p_handshake(
            signature,
            &pub_key,
            resp_id,
            &my_id,
            timestamp_ms,
        )
        .map_err(|e| {
            let err = format!("responder handshake signature verification failed: {}", e);
            err
        })?;

        let connection_id = uuid::Uuid::new_v4();
        let (tx, rx) = mpsc::channel(100);
        get_active_tunnels()
            .lock()
            .await
            .insert(target_node_id.clone(), TunnelSession { tx, connection_id });


        if let Some(sig_tx) = SIGNAL_TX.get() {
            let _ = sig_tx
                .send(LocalMeshSignal::TunnelEstablished(target_node_id.clone()))
                .await;
        }

        let target_node_id_clone = target_node_id.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            let _ = run_tunnel_loop(
                stream,
                session,
                rx,
                target_node_id_clone,
                my_id,
                connection_id,
                config_clone,
            )
            .await;
        });

        if let Some(tunnels) = ACTIVE_TCP_TUNNELS.get() {
            if let Some(session) = tunnels.lock().await.get(&target_node_id) {
                let _ = session.tx.send(P2pMessage::RequestTopology).await;
            }
        }

        Ok(())
    } else {
        Err("Invalid Handshake response".to_string())
    }
}

async fn run_tunnel_loop(
    mut stream: TcpStream,
    mut session: snow::TransportState,
    mut rx: mpsc::Receiver<P2pMessage>,
    remote_node_id: String,
    my_id: String,
    connection_id: uuid::Uuid,
    config: client_config::AppConfig,
) -> Result<(), String> {
    loop {
        tokio::select! {
            msg_opt = rx.recv() => {
                if let Some(msg) = msg_opt {
                    let envelope = nodeinnet_p2p::SecuredP2pEnvelope { mac: None, message: msg };
                    if let Ok(bytes) = serde_json::to_vec(&envelope) {
                        let mut enc_buf = vec![0u8; bytes.len() + 1024];
                        if let Ok(enc_len) = session.write_message(&bytes, &mut enc_buf) {
                            if write_packet(&mut stream, &enc_buf[..enc_len]).await.is_err() {
                                break;
                            }
                        }
                    }
                } else {
                    break;
                }
            }

            pkt_res = read_packet(&mut stream) => {
                match pkt_res {
                    Ok(pkt) => {
                        let mut dec_buf = vec![0u8; pkt.len() + 1024];
                        if let Ok(dec_len) = session.read_message(&pkt, &mut dec_buf) {
                            if let Ok(envelope) = serde_json::from_slice::<nodeinnet_p2p::SecuredP2pEnvelope>(&dec_buf[..dec_len]) {
                                handle_tunnel_message(envelope.message, &remote_node_id, &my_id, &config).await;
                            }
                        }
                    }
                    Err(_e) => {
                        break;
                    }
                }
            }
        }
    }


    let mut tunnels = get_active_tunnels().lock().await;
    if let Some(current_session) = tunnels.get(&remote_node_id) {
        if current_session.connection_id == connection_id {
            tunnels.remove(&remote_node_id);
        }
    }
    Ok(())
}

async fn handle_tunnel_message(
    msg: P2pMessage,
    remote_node_id: &str,
    my_id: &str,
    config: &client_config::AppConfig,
) {
    match msg {
        P2pMessage::RtcSignal {
            target_node_id,
            signal_type,
            sdp_or_candidate,
            sdp_mid,
            sdp_mline_index,
        } => {
            if target_node_id == my_id {
                if let Some(tx) = SIGNAL_TX.get() {
                    let _ = tx
                        .send(LocalMeshSignal::InboundRtcSignal {
                            from_node_id: remote_node_id.to_string(),
                            signal_type,
                            sdp_or_candidate,
                            sdp_mid,
                            sdp_mline_index,
                        })
                        .await;
                }
            } else {
                let tunnels = get_active_tunnels().lock().await;
                if let Some(session) = tunnels.get(&target_node_id) {
                    let routed_msg = P2pMessage::RtcSignal {
                        target_node_id,
                        signal_type,
                        sdp_or_candidate,
                        sdp_mid,
                        sdp_mline_index,
                    };
                    let _ = session.tx.send(routed_msg).await;
                }
            }
        }

        P2pMessage::RequestTopology => {
            let tunnels = get_active_tunnels().lock().await;
            let mut peers = Vec::new();
            for peer_id in tunnels.keys() {
                if let Some(pub_key) = nodeinnet_p2p::get_known_public_key(peer_id) {
                    let last_known_addresses = config
                        .get::<std::collections::HashMap<String, nodeinnet_p2p::PeerConfig>>(
                            "peers",
                        )
                        .unwrap_or_default()
                        .get(peer_id)
                        .map(|p| p.last_known_addresses.clone())
                        .unwrap_or_default();

                    peers.push(NodeTopologyInfo {
                        id: peer_id.clone(),
                        name: peer_id.clone(),
                        public_key: pub_key,
                        last_known_addresses,
                    });
                }
            }
            if let Some(session) = tunnels.get(remote_node_id) {
                let _ = session
                    .tx
                    .send(P2pMessage::ResponseTopology { peers })
                    .await;
            }
        }

        P2pMessage::ResponseTopology { peers } => {
            for peer in peers {
                if peer.id == my_id {
                    continue;
                }

                if nodeinnet_p2p::get_known_public_key(&peer.id).is_none() {
                    let node_info = NodeInfo {
                        id: peer.id.clone(),
                        name: peer.name.clone(),
                        os: "unknown".to_string(),
                        version: "0.1.0".to_string(),
                        app_type: "desktop".to_string(),
                        build_type: "debug".to_string(),
                        public_key: peer.public_key.clone(),
                        resources: vec![],
                        is_online: false,
                        last_used: 0,
                        is_temporary: false,
                    };
                    nodeinnet_p2p::update_known_public_keys(&[node_info]);
                    config.update(
                        "peers",
                        |map: &mut std::collections::HashMap<String, nodeinnet_p2p::PeerConfig>| {
                            let entry = map.entry(peer.id.clone()).or_default();
                            entry.public_key = peer.public_key.clone();
                            entry.name = peer.name.clone();
                        },
                    );
                }

                if !peer.last_known_addresses.is_empty() {
                    config.update(
                        "peers",
                        |map: &mut std::collections::HashMap<String, nodeinnet_p2p::PeerConfig>| {
                            let entry = map.entry(peer.id.clone()).or_default();
                            for addr in &peer.last_known_addresses {
                                if !entry.last_known_addresses.contains(addr) {
                                    entry.last_known_addresses.push(addr.clone());
                                }
                            }
                        },
                    );
                }
            }
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn valid_32_byte_key_decodes_and_hashes() {
        let key_bytes = [0u8; 32];
        let b64 = general_purpose::STANDARD_NO_PAD.encode(key_bytes);
        let result = get_noise_private_key(&b64);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn wrong_length_key_returns_error() {
        let short_bytes = [0u8; 16];
        let b64 = general_purpose::STANDARD_NO_PAD.encode(short_bytes);
        let result = get_noise_private_key(&b64);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key size"));
    }

    #[test]
    fn invalid_base64_returns_error() {
        let result = get_noise_private_key("not!valid!base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn different_keys_produce_different_hashes() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let b64_1 = general_purpose::STANDARD_NO_PAD.encode(key1);
        let b64_2 = general_purpose::STANDARD_NO_PAD.encode(key2);
        let h1 = get_noise_private_key(&b64_1).unwrap();
        let h2 = get_noise_private_key(&b64_2).unwrap();
        assert_ne!(h1, h2);
    }


    #[tokio::test]
    async fn write_then_read_packet_roundtrip() {
        let data = b"hello p2p tunnel";
        let mut buf = std::io::Cursor::new(Vec::new());
        write_packet(&mut buf, data).await.unwrap();
        buf.set_position(0);
        let read_back = read_packet(&mut buf).await.unwrap();
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn empty_packet_roundtrip() {
        let mut buf = std::io::Cursor::new(Vec::new());
        write_packet(&mut buf, b"").await.unwrap();
        buf.set_position(0);
        let read_back = read_packet(&mut buf).await.unwrap();
        assert!(read_back.is_empty());
    }


    #[tokio::test]
    async fn active_tunnels_initializes_and_is_lockable() {
        let tunnels = get_active_tunnels();
        let guard = tunnels.lock().await;
        let _ = guard.len(); // just verify lock works
    }
}
