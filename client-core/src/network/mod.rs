pub mod manager;
pub mod p2p_transfer;
pub mod peer_orchestrator;
pub mod types;
pub mod ws_client;

pub use manager::NetworkManager;
pub use types::{NetworkMode, PeerBackoff};

use crate::{AppEventHandler, NetCmd};
use nodeinnet_p2p::rtc::{RtcSignal, RtcSignalEnvelope};
use nodeinnet_p2p::{NodeInfo, P2pMessage, WsMessage};
use std::sync::Arc;
use std::thread;
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;

pub async fn route_rtc_signal(
    envelope: RtcSignalEnvelope,
    current_ws_tx: &Option<tokio_mpsc::Sender<WsMessage>>,
    handler: &Arc<dyn AppEventHandler>,
) {
    let mut routed = false;
    let signal_name = match &envelope.signal {
        RtcSignal::Offer { .. } => "Offer",
        RtcSignal::Answer { .. } => "Answer",
        RtcSignal::IceCandidate { .. } => "IceCandidate",
    };

    let _ = handler
        .on_log(format!(
            "📡 [route_rtc_signal] Routing RTC {} to node {}",
            signal_name, envelope.to_node_id
        ))
        .await;

    for attempt in 1..=10 {
        if let Some(tunnels) = p2p_node::local_mesh::ACTIVE_TCP_TUNNELS.get() {
            let tunnels_map = tunnels.lock().await;
            if let Some(session) = tunnels_map.get(&envelope.to_node_id) {
                let p2p_msg = match &envelope.signal {
                    RtcSignal::Offer { sdp, .. } => P2pMessage::RtcSignal {
                        target_node_id: envelope.to_node_id.clone(),
                        signal_type: "offer".to_string(),
                        sdp_or_candidate: sdp.clone(),
                        sdp_mid: None,
                        sdp_mline_index: None,
                    },
                    RtcSignal::Answer { sdp } => P2pMessage::RtcSignal {
                        target_node_id: envelope.to_node_id.clone(),
                        signal_type: "answer".to_string(),
                        sdp_or_candidate: sdp.clone(),
                        sdp_mid: None,
                        sdp_mline_index: None,
                    },
                    RtcSignal::IceCandidate {
                        candidate,
                        sdp_mid,
                        sdp_mline_index,
                    } => P2pMessage::RtcSignal {
                        target_node_id: envelope.to_node_id.clone(),
                        signal_type: "candidate".to_string(),
                        sdp_or_candidate: candidate.clone(),
                        sdp_mid: sdp_mid.clone(),
                        sdp_mline_index: *sdp_mline_index,
                    },
                };
                match session.tx.send(p2p_msg).await {
                    Ok(_) => {
                        routed = true;
                        let _ = handler.on_log(format!("📡 [route_rtc_signal] Successfully routed RTC {} to {} tunnel (attempt {})", signal_name, envelope.to_node_id, attempt)).await;
                    }
                    Err(e) => {
                        let _ = handler
                            .on_log(format!(
                                "❌ [route_rtc_signal] Failed to send to tunnel channel for {}: {}",
                                envelope.to_node_id, e
                            ))
                            .await;
                    }
                }
                break;
            } else {
                let keys: Vec<String> = tunnels_map.keys().cloned().collect();
                let _ = handler.on_log(format!("📡 [route_rtc_signal] Attempt {}/10: Peer {} not in ACTIVE_TCP_TUNNELS (available keys: {:?})", attempt, envelope.to_node_id, keys)).await;
            }
        } else {
            let _ = handler
                .on_log(format!(
                    "📡 [route_rtc_signal] Attempt {}/10: ACTIVE_TCP_TUNNELS is not initialized",
                    attempt
                ))
                .await;
        }

        if current_ws_tx.is_some() {
            let _ = handler
                .on_log("📡 [route_rtc_signal] Cloud WS is connected, breaking tunnel retry loop".to_string())
                .await;
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    if routed {
        return;
    }

    if let Some(tx) = current_ws_tx {
        let _ = handler
            .on_log(format!(
                "📡 [route_rtc_signal] Routing RTC {} over Cloud WS to {}",
                signal_name, envelope.to_node_id
            ))
            .await;
        let _ = tx.send(WsMessage::RtcSignal(envelope)).await;
    } else {
        let _ = handler
            .on_log(format!(
                "⚠️ Failed to route RtcSignal {} to {}: offline and no active TCP tunnel",
                signal_name, envelope.to_node_id
            ))
            .await;
    }
}

pub fn trigger_cached_peer_reconnections(
    my_id: String,
    private_key_b64: String,
    peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
) {
    tokio::spawn(async move {
        let cached_map: std::collections::HashMap<String, nodeinnet_p2p::PeerConfig> =
            peer_store.load();
        for (peer_id, peer) in cached_map {
            let addrs = peer.last_known_addresses;
            if peer_id == my_id {
                continue;
            }

            let connected = {
                if let Some(tunnels) = p2p_node::local_mesh::ACTIVE_TCP_TUNNELS.get() {
                    tunnels.lock().await.contains_key(&peer_id)
                } else {
                    false
                }
            };

            if !connected {
                for addr in addrs {
                    let addr_clone = addr.clone();
                    let peer_id_clone = peer_id.clone();
                    let my_id_clone = my_id.clone();
                    let private_key_b64_clone = private_key_b64.clone();
                    let peer_store_clone = peer_store.clone();
                    tokio::spawn(async move {
                        let _ = p2p_node::local_mesh::connect_to_peer_signaling(
                            addr_clone,
                            peer_id_clone,
                            my_id_clone,
                            private_key_b64_clone,
                            peer_store_clone,
                        )
                        .await;
                    });
                }
            }
        }
    });
}

pub fn start_network_thread(
    net_rx: tokio_mpsc::Receiver<NetCmd>,
    net_tx: tokio_mpsc::Sender<NetCmd>,
    handler: Arc<dyn AppEventHandler>,
    my_info: NodeInfo,
    private_key: String,
    peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
    enable_local_discovery: bool,
) {
    thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(run_network_manager(
            net_rx,
            net_tx,
            handler,
            my_info,
            private_key,
            peer_store,
            enable_local_discovery,
        ));
    });
}

pub async fn run_network_manager(
    mut net_rx: tokio_mpsc::Receiver<NetCmd>,
    net_tx: tokio_mpsc::Sender<NetCmd>,
    handler: Arc<dyn AppEventHandler>,
    my_info: NodeInfo,
    private_key: String,
    peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
    enable_local_discovery: bool,
) {
    let mut manager = NetworkManager::new(
        my_info,
        private_key.clone(),
        handler.clone(),
        net_tx.clone(),
        peer_store.clone(),
    );

    let peers: std::collections::HashMap<String, nodeinnet_p2p::PeerConfig> =
        peer_store.load();
    let mut cached_peers_log = format!(
        "📁 Loaded {} cached peers from the host store on startup:\n",
        peers.len()
    );
    for (id, peer) in &peers {
        cached_peers_log.push_str(&format!("  - {} ({}, OS: {})\n", peer.name, id, peer.os));
    }
    let _ = manager.handler.on_log(cached_peers_log).await;
    let mut initial_nodes = Vec::new();
    for (id, peer) in peers {
        if id == manager.my_info.id {
            continue;
        }
        if peer.os == "web" || peer.name == "Web Browser Node" {
            continue;
        }
        initial_nodes.push(NodeInfo {
            id: id.clone(),
            name: peer.name,
            os: peer.os,
            version: "0.1.0".to_string(),
            app_type: "desktop".to_string(),
            build_type: "debug".to_string(),
            public_key: peer.public_key,
            resources: vec![],
            is_online: false,
            last_used: 0,
            is_temporary: false,
        });
    }
    if !initial_nodes.is_empty() {
        nodeinnet_p2p::update_known_public_keys(&initial_nodes);
        for node in &initial_nodes {
            manager
                .last_known_nodes
                .insert(node.id.clone(), node.clone());
        }
        let all_nodes: Vec<NodeInfo> = manager.last_known_nodes.values().cloned().collect();
        let _ = manager.handler.on_update_nodes(all_nodes).await;
    }

    if enable_local_discovery {
        manager.start_local_discovery();
    }

    let (signal_tx, mut signal_rx) = tokio_mpsc::channel(100);
    // `SIGNAL_TX` is a process-wide `OnceLock`. A SECOND manager in the same process finds.
    let mut _unused_signal_tx = None;
    if let Err(returned) = p2p_node::local_mesh::SIGNAL_TX.set(signal_tx) {
        let _ = handler
            .on_log(
                "⚠️ [Network] local-mesh signal channel was already claimed by an earlier \
                 network manager in this process; this one will not receive local-mesh signals"
                    .to_string(),
            )
            .await;
        _unused_signal_tx = Some(returned);
    }

    let mut reconnect_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut local_mesh_open = true;

    loop {
        tokio::select! {
            _ = reconnect_interval.tick() => {
                manager.handle_tick().await;
            }
            cmd_opt = net_rx.recv() => {
                if let Some(cmd) = cmd_opt {
                    manager.handle_net_cmd(cmd).await;
                } else {
                    break;
                }
            }
            signal_opt = signal_rx.recv(), if local_mesh_open => {
                match signal_opt {
                    Some(signal) => manager.handle_local_mesh_signal(signal).await,
                    None => local_mesh_open = false,
                }
            }
        }
    }
}

pub fn spawn_network_task(
    net_rx: tokio_mpsc::Receiver<NetCmd>,
    net_tx: tokio_mpsc::Sender<NetCmd>,
    handler: Arc<dyn AppEventHandler>,
    my_info: NodeInfo,
    private_key: String,
    peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
    enable_local_discovery: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_network_manager(
        net_rx,
        net_tx,
        handler,
        my_info,
        private_key,
        peer_store,
        enable_local_discovery,
    ))
}
