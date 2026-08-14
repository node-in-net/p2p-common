use nodeinnet_p2p::P2pMessage;
use p2p_node::NodeContext;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use webrtc::data_channel::RTCDataChannel;

pub async fn handle_core_message(
    p2p_msg: P2pMessage,
    handler: std::sync::Arc<dyn crate::AppEventHandler>,
    dc: Arc<RTCDataChannel>,
    node_context: NodeContext,
    target_node_id: String,
    last_pong: Arc<AtomicU64>,
    peer_connection: Arc<webrtc::peer_connection::RTCPeerConnection>,
) {
    match p2p_msg {
        P2pMessage::TextMessage { text } => {
            handler.on_log(format!("📦 [WebRTC Msg]: {}", text)).await;
        }
        P2pMessage::Handshake { 
            node_version,
            timestamp_ms,
            signature,
            requested_resources,
            max_chunk_size: peer_max_chunk_size_req,
            local_tcp_port,
            from_node_id,
        } => {
            handler.on_log(format!(
                "🤝 Handshake Check. Verifying Zero-Trust Identity of {}...",
                target_node_id
            )).await;

            let my_id = node_context.my_info.id.clone();
            
            // Replay Attack Validation
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
            if now > timestamp_ms && now - timestamp_ms > 60_000 {
                handler.on_log(format!("❌ Zero-Trust Auth Rejected: Timestamp too old (replay attack prevention) for {}.", target_node_id)).await;
                handler.on_peer_state_changed(target_node_id.clone(), crate::P2pPeerState::Failed).await;
                let _ = dc.close().await;
                return;
            }

            let mut found_pub_key = None;
            for _ in 0..10 {
                if let Some(pub_key) = nodeinnet_p2p::get_known_public_key(&target_node_id) {
                    found_pub_key = Some(pub_key);
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }

            match found_pub_key {
                Some(pub_key) => {
                    if let Err(e) = nodeinnet_p2p::crypto::verify_p2p_handshake(
                        &signature, 
                        &pub_key, 
                        &target_node_id, 
                        &my_id, 
                        timestamp_ms
                    ) {
                        handler.on_log(format!("❌ Zero-Trust Crypto Verification FAILED for {}: {}", target_node_id, e)).await;
                        handler.on_peer_state_changed(target_node_id.clone(), crate::P2pPeerState::Failed).await;
                        let _ = dc.close().await;
                        return;
                    }
                }
                None => {
                    handler.on_log(format!("❌ Zero-Trust Auth Rejected: No trusted public key found for {} (timeout 5s). Is peer registered?", target_node_id)).await;
                    handler.on_peer_state_changed(target_node_id.clone(), crate::P2pPeerState::Failed).await;
                    let _ = dc.close().await;
                    return;
                }
            }

            handler.on_log(format!("✅ Zero-Trust Cryptographic Connection authenticated with {}", target_node_id)).await;
            node_context.is_authenticated.store(true, std::sync::atomic::Ordering::Relaxed);
            handler.on_p2p_connected(target_node_id.clone()).await;
            crate::rtc::spawn_connection_type_poller(peer_connection.clone(), target_node_id.clone(), handler.clone());

            // Cache discovered IP addresses with the remote TCP port on successful zero-trust authentication
            if let Some(port) = local_tcp_port {
                let ips = node_context.discovered_ips.lock().await;
                if !ips.is_empty() {
                    handler.on_log(format!("💾 [CACHE] Caching last known peer IPs for {}: {:?} on port {}", target_node_id, *ips, port)).await;
                    node_context.config.update("peers", |map: &mut std::collections::HashMap<String, nodeinnet_p2p::PeerConfig>| {
                        let entry = map.entry(target_node_id.clone()).or_default();
                        entry.last_known_addresses = ips.iter().map(|ip| format!("{}:{}", ip, port)).collect();
                    });
                }
            }

            // Dynamic negotiation of chunk sizes
            if let Some(c_size) = peer_max_chunk_size_req {
                node_context.peer_max_chunk_size.store(c_size, std::sync::atomic::Ordering::Relaxed);
                handler.on_log(format!("⚙️ Peer negotiated max chunk size: {} bytes", c_size)).await;
            }

            // The Callee handles the Handshake and generates HandshakeResponse containing its resources and keys!
            node_context.process_message(P2pMessage::Handshake { 
                node_version, 
                timestamp_ms, 
                signature, 
                requested_resources, 
                max_chunk_size: peer_max_chunk_size_req,
                local_tcp_port,
                from_node_id,
            }).await;
        }
        P2pMessage::Goodbye => {
            handler.on_log(format!("👋 Peer {} sent Goodbye. Closing connection.", target_node_id)).await;
            node_context.shutdown().await;
            let _ = dc.close().await;
        }
        P2pMessage::Ping(ts) => {
            let envelope = nodeinnet_p2p::SecuredP2pEnvelope { mac: None, message: P2pMessage::Pong(ts) };
            if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&envelope) {
                let max_c = 10240;
                let _ = crate::rtc::send_chunked_binary(&dc, &bson_bytes, max_c, &handler, &node_context.dc_write_lock).await;
            }
        }
        P2pMessage::Pong(ts) => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
            last_pong.store(now, Ordering::Relaxed);
            let rtt = now - ts;
            handler.on_log(format!("🏓 P2P Pong received! RTT: {}ms", rtt)).await;
            handler.on_p2p_ping_updated(target_node_id.clone(), rtt).await;
        }
        P2pMessage::EntriesResponse { .. }
        | P2pMessage::MetadataResponse { .. }
        | P2pMessage::CreateDirectoryResponse { .. }
        | P2pMessage::DeleteEntryResponse { .. }
        | P2pMessage::RenameEntryResponse { .. }
        | P2pMessage::SystemInfoResponse { .. }
        | P2pMessage::RegistryKeysResponse { .. }
        | P2pMessage::CreateRegistryKeyResponse { .. }
        | P2pMessage::DeleteRegistryEntryResponse { .. }
        | P2pMessage::SetRegistryValueResponse { .. }
        | P2pMessage::HttpResponseStart { .. }
        | P2pMessage::HttpResponseChunk { .. }
        | P2pMessage::HttpResponseComplete { .. }
        | P2pMessage::FileTransferComplete { .. } // we also handled this in filemanager, but here it's an end to avoid the unhandled log
        | P2pMessage::FileTransferResponse { .. }
        | P2pMessage::FileChunk { .. }
        | P2pMessage::TerminalOutput { .. } 
        | P2pMessage::SocksConnectResponse { .. } => {
            // Already sent to UI thread
        }
        _other => {
            // Any other messages not handled fall through.
            // p2p-node processes them successfully, so NO error log is needed!
        }
    }
}
