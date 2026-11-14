use super::manager::NetworkManager;
use super::types::{NetworkMode, PeerBackoff, get_cooldown_duration};
use crate::NetCmd;
use nodeinnet_p2p::NodeInfo;
use nodeinnet_p2p::rtc::{RtcSignal, RtcSignalEnvelope};
use p2p_node::lan::Link;

impl NetworkManager {
    pub async fn handle_tick(&mut self) {
        self.reap_stuck_lan_sessions().await;
        match self.mode {
            NetworkMode::WebSocketConnected => {
                let online_targets: Vec<String> = self
                    .last_known_nodes
                    .values()
                    .filter(|node| {
                        node.app_type != "web"
                            && (node.id > self.my_info.id
                                || self.focused_peer == Some(node.id.clone()))
                            && node.is_online
                            && !self.active_peers.contains_key(&node.id)
                    })
                    .map(|node| node.id.clone())
                    .collect();

                for node_id in online_targets {
                    let should_retry = if let Some(backoff) = self.backoff_states.get(&node_id) {
                        let cooldown = get_cooldown_duration(backoff.attempt_count);
                        backoff.last_attempt.elapsed() >= cooldown
                    } else {
                        true
                    };

                    if should_retry {
                        let _ = self.net_tx_bg.send(NetCmd::AutoConnect(node_id));
                    }
                }
            }
            NetworkMode::LocalMeshFallback | NetworkMode::WebSocketConnecting => {}
        }
    }

    pub async fn handle_peer_cmd(&mut self, cmd: NetCmd) {
        match cmd {
            NetCmd::DisconnectPeer(node_id)
                if self
                    .active_peers
                    .get(&node_id)
                    .is_some_and(|peer| peer.link != Link::Account) =>
            {
                self.end_lan_session(&node_id).await;
            }
            NetCmd::DisconnectPeerSession(node_id, conn_id)
                if self.active_peers.get(&node_id).is_some_and(|peer| {
                    peer.link != Link::Account && peer.connection_id == conn_id
                }) =>
            {
                self.end_lan_session(&node_id).await;
            }
            NetCmd::HandleInboundSignal(inbound, link)
                if self
                    .active_peers
                    .get(&inbound.from_node_id)
                    .is_some_and(|peer| peer.link != link) =>
            {
                self.handler
                    .on_log(format!(
                        "🚫 [Inbound] Signal from {} ignored: its session runs over the other link",
                        inbound.from_node_id
                    ))
                    .await;
            }
            NetCmd::HandleInboundSignal(inbound, Link::Account)
                if self.lan_knows(&inbound.from_node_id) =>
            {
                self.handler
                    .on_log(format!(
                        "🚫 [Inbound] Account signal from {} ignored: it is a local-network device",
                        inbound.from_node_id
                    ))
                    .await;
            }
            NetCmd::AutoConnect(node_id) | NetCmd::Call(node_id)
                if self.lan_knows(&node_id)
                    || self
                        .active_peers
                        .get(&node_id)
                        .is_some_and(|peer| peer.link != Link::Account) =>
            {
                self.handler
                    .on_log(format!(
                        "⏭️ {} is a local-network device; not dialling it through the account",
                        node_id
                    ))
                    .await;
            }
            NetCmd::DisconnectPeer(node_id) => {
                if let Some(peer) = self.active_peers.remove(&node_id) {
                    self.handler
                        .on_log(format!("🔴 Dropped active P2P session with {}", node_id))
                        .await;
                    peer.end_session().await;

                    let handler_clone = self.handler.clone();
                    let node_id_clone = node_id.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                        let pc = peer.peer_connection.clone();
                        drop(peer);
                        let _ = pc.close().await;
                        handler_clone.on_p2p_disconnected(node_id_clone).await;
                    });
                }
                if self.focused_peer == Some(node_id.clone()) {
                    self.focused_peer = None;
                }

                let backoff = self
                    .backoff_states
                    .entry(node_id.clone())
                    .or_insert_with(|| PeerBackoff {
                        attempt_count: 0,
                        last_attempt: std::time::Instant::now(),
                        is_connected: false,
                    });
                if backoff.is_connected {
                    backoff.is_connected = false;
                    backoff.attempt_count = 1;
                    backoff.last_attempt = std::time::Instant::now();
                    self.handler
                        .on_log(format!(
                            "⚠️ [Backoff] Peer {} disconnected. Next retry in 5s.",
                            node_id
                        ))
                        .await;
                } else {
                    backoff.last_attempt = std::time::Instant::now();
                    let next_cooldown = get_cooldown_duration(backoff.attempt_count);
                    self.handler
                        .on_log(format!(
                            "⚠️ [Backoff] Connection attempt to {} failed. Next retry in {}s.",
                            node_id,
                            next_cooldown.as_secs()
                        ))
                        .await;
                }
            }
            NetCmd::DisconnectPeerSession(node_id, conn_id) => {
                let should_remove = if let Some(peer) = self.active_peers.get(&node_id) {
                    peer.connection_id == conn_id
                } else {
                    false
                };
                if should_remove {
                    if let Some(peer) = self.active_peers.remove(&node_id) {
                        self.handler
                            .on_log(format!(
                                "🔴 Dropped active P2P session with {} (session ID: {})",
                                node_id, conn_id
                            ))
                            .await;
                        peer.end_session().await;
                        let handler_clone = self.handler.clone();
                        let node_id_clone = node_id.clone();
                        tokio::spawn(async move {
                            let pc = peer.peer_connection.clone();
                            drop(peer);
                            let _ = pc.close().await;
                            handler_clone.on_p2p_disconnected(node_id_clone).await;
                        });
                    }
                    if self.focused_peer == Some(node_id.clone()) {
                        self.focused_peer = None;
                    }
                    let backoff = self
                        .backoff_states
                        .entry(node_id.clone())
                        .or_insert_with(|| PeerBackoff {
                            attempt_count: 0,
                            last_attempt: std::time::Instant::now(),
                            is_connected: false,
                        });
                    if backoff.is_connected {
                        backoff.is_connected = false;
                        backoff.attempt_count = 1;
                        backoff.last_attempt = std::time::Instant::now();
                        self.handler
                            .on_log(format!(
                                "⚠️ [Backoff] Peer {} disconnected. Next retry in 5s.",
                                node_id
                            ))
                            .await;
                    } else {
                        backoff.last_attempt = std::time::Instant::now();
                        let next_cooldown = get_cooldown_duration(backoff.attempt_count);
                        self.handler
                            .on_log(format!(
                                "⚠️ [Backoff] Connection attempt to {} failed. Next retry in {}s.",
                                node_id,
                                next_cooldown.as_secs()
                            ))
                            .await;
                    }
                } else {
                    self.handler
                        .on_log(format!(
                            "⏭️ Ignoring stale DisconnectPeerSession for {} (session ID: {})",
                            node_id, conn_id
                        ))
                        .await;
                }
            }
            NetCmd::PeerConnected(node_id, resources) => {
                let backoff = self
                    .backoff_states
                    .entry(node_id.clone())
                    .or_insert_with(|| PeerBackoff {
                        attempt_count: 0,
                        last_attempt: std::time::Instant::now(),
                        is_connected: true,
                    });
                backoff.is_connected = true;
                backoff.attempt_count = 0;

                if let Some(node) = self.last_known_nodes.get_mut(&node_id) {
                    node.resources = resources.clone();
                    node.is_online = true;
                } else {
                    let pub_key = nodeinnet_p2p::get_known_public_key(&node_id).unwrap_or_default();
                    let node = NodeInfo {
                        id: node_id.clone(),
                        name: node_id.clone(),
                        os: "unknown".to_string(),
                        version: "0.1.0".to_string(),
                        app_type: "desktop".to_string(),
                        build_type: "debug".to_string(),
                        public_key: pub_key,
                        resources: resources.clone(),
                        is_online: true,
                        last_used: 0,
                        is_temporary: false,
                    };
                    self.last_known_nodes.insert(node_id.clone(), node);
                }

                let all_nodes: Vec<NodeInfo> = self.last_known_nodes.values().cloned().collect();
                let _ = self.handler.on_update_nodes(all_nodes).await;

                self.handler
                    .on_log(format!(
                        "✨ [Backoff] Peer {} successfully connected. Backoff reset.",
                        node_id
                    ))
                    .await;
            }
            NetCmd::HandleInboundSignal(inbound, link) => match inbound.signal {
                RtcSignal::Offer { sdp, ice_restart } => {
                    self.handler
                        .on_log(format!(
                            "📥 Received Offer from {}. Generating Answer...",
                            inbound.from_node_id
                        ))
                        .await;
                    self.handler
                        .on_log(format!(
                            "📡 [ROLE] We are the ANSWERER for node {} (accepting the incoming call)",
                            inbound.from_node_id
                        ))
                        .await;

                    if ice_restart
                        && let Some(existing) = self.active_peers.get(&inbound.from_node_id)
                    {
                        self.handler
                                .on_log(format!(
                                    "♻️ [ICE Restart] In-place renegotiation for {} (session preserved)",
                                    inbound.from_node_id
                                ))
                                .await;
                        match existing.accept_offer_and_answer(sdp).await {
                            Ok(answer_sdp) => {
                                let answer = RtcSignal::Answer { sdp: answer_sdp };
                                self.send_signal(link, inbound.from_node_id.clone(), answer)
                                    .await;
                            }
                            Err(e) => {
                                self.handler
                                        .on_log(format!(
                                            "❌ [ICE Restart] Failed to answer restart offer from {}: {}",
                                            inbound.from_node_id, e
                                        ))
                                        .await;
                            }
                        }
                        return;
                    }

                    if link != Link::Account && !self.lan_admits_session(&inbound.from_node_id) {
                        self.handler
                            .on_log(format!(
                                "🚫 [LAN] Offer from {} refused: not trusted here, or hidden",
                                inbound.from_node_id
                            ))
                            .await;
                        return;
                    }
                    if link != Link::Account && self.lan_offer_stands(&inbound.from_node_id) {
                        self.handler
                            .on_log(format!(
                                "⏭️ [LAN] Offers crossed with {}; ours stands",
                                inbound.from_node_id
                            ))
                            .await;
                        return;
                    }

                    let is_duplicate = {
                        if let Some(existing) = self.active_peers.get(&inbound.from_node_id) {
                            if let Some(rd) = existing.peer_connection.remote_description().await {
                                rd.sdp == sdp
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };

                    if is_duplicate {
                        self.handler
                            .on_log(format!(
                                "⏭️ [Inbound] Ignoring duplicate Offer from {}",
                                inbound.from_node_id
                            ))
                            .await;
                    } else if !super::types::peer_slot_available(
                        &self.active_peers,
                        &inbound.from_node_id,
                    ) {
                        self.handler
                            .on_log(format!(
                                "🚧 [Limit] Refusing offer from {}: peer limit of {} already reached",
                                inbound.from_node_id,
                                crate::limits::max_peers()
                            ))
                            .await;
                    } else {
                        self.handler
                            .on_p2p_connecting(inbound.from_node_id.clone())
                            .await;
                        self.handler
                            .on_peer_state_changed(
                                inbound.from_node_id.clone(),
                                crate::P2pPeerState::ConnectingTransport,
                            )
                            .await;

                        if let Some(old_client) = self.active_peers.remove(&inbound.from_node_id) {
                            if old_client.link != Link::Account {
                                self.lan_dials.remove(&inbound.from_node_id);
                                if let Some(lan) = &self.lan {
                                    lan.session(&inbound.from_node_id, None);
                                }
                            }
                            self.handler
                                .on_log(format!(
                                    "🧹 [Inbound] Replacing existing WebRTC client for {}",
                                    inbound.from_node_id
                                ))
                                .await;
                            old_client.end_session().await;
                            let pc = old_client.peer_connection.clone();
                            drop(old_client);
                            let _peer_id = inbound.from_node_id.clone();
                            tokio::spawn(async move {
                                let _ = pc.close().await;
                            });
                        }
                        match crate::rtc::WebRtcClient::new(
                            self.handler.clone(),
                            self.net_tx_bg.clone(),
                            self.my_info_for(&inbound.from_node_id, &link),
                            inbound.from_node_id.clone(),
                            self.private_key.clone(),
                            self.current_turn_credentials.clone(),
                            self.peer_store.clone(),
                            link,
                        )
                        .await
                        {
                            Ok(rtc_client) => match rtc_client.accept_offer_and_answer(sdp).await {
                                Ok(answer_sdp) => {
                                    let answer = RtcSignal::Answer { sdp: answer_sdp };
                                    self.send_signal(link, inbound.from_node_id.clone(), answer)
                                        .await;
                                    self.active_peers
                                        .insert(inbound.from_node_id.clone(), rtc_client);
                                }
                                Err(e) => {
                                    self.handler
                                        .on_log(format!("❌ Failed to answer offer: {}", e))
                                        .await;
                                }
                            },
                            Err(e) => {
                                self.handler
                                    .on_log(format!("❌ Failed to init WebRTC: {}", e))
                                    .await;
                            }
                        }
                    }
                }
                RtcSignal::Answer { sdp } => {
                    self.handler
                        .on_log(format!(
                            "📥 Received Answer from {}. Applying it...",
                            inbound.from_node_id
                        ))
                        .await;
                    if let Some(rtc) = self.active_peers.get(&inbound.from_node_id) {
                        if let Err(e) = rtc.apply_answer(sdp).await {
                            self.handler
                                .on_log(format!("❌ Failed to apply answer: {}", e))
                                .await;
                        } else {
                            self.handler
                                .on_log(format!(
                                    "✅ Successfully applied Answer from {}",
                                    inbound.from_node_id
                                ))
                                .await;
                        }
                    } else {
                        self.handler
                            .on_log(format!(
                                "⚠️ Received Answer from {} but they are not in active_peers!",
                                inbound.from_node_id
                            ))
                            .await;
                    }
                }
                RtcSignal::IceCandidate {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                } => {
                    self.handler
                        .on_log(format!(
                            "📥 Received ICE candidate from {}",
                            inbound.from_node_id
                        ))
                        .await;
                    if let Some(rtc) = self.active_peers.get(&inbound.from_node_id) {
                        if let Err(e) = rtc
                            .add_ice_candidate(candidate, sdp_mid, sdp_mline_index)
                            .await
                        {
                            self.handler
                                .on_log(format!("❌ Failed to add ICE candidate: {}", e))
                                .await;
                        }
                    } else {
                        self.handler.on_log(format!("⚠️ Received ICE candidate from {} but they are not in active_peers!", inbound.from_node_id)).await;
                    }
                }
            },
            NetCmd::AutoConnect(node_id) => {
                let backoff = self
                    .backoff_states
                    .entry(node_id.clone())
                    .or_insert_with(|| PeerBackoff {
                        attempt_count: 0,
                        last_attempt: std::time::Instant::now(),
                        is_connected: false,
                    });

                if let Some(peer) = self.active_peers.get(&node_id) {
                    let state = peer.peer_connection.connection_state();
                    let stuck_timeout_secs = crate::limits::timeouts()
                        .dial_stuck(backoff.attempt_count)
                        .as_secs();
                    let is_stuck = (state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::New || state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Connecting) && peer.created_at.elapsed().as_secs() > stuck_timeout_secs;
                    let is_dead = state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Disconnected || state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Failed || state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Closed;

                    if is_stuck || is_dead {
                        self.handler.on_log(format!("⚠️ [AutoConnect] Peer {} is in stuck/dead state {:?}. Reaping it...", node_id, state)).await;
                        let _ = self.net_tx_bg.send(NetCmd::DisconnectPeer(node_id.clone()));
                        return;
                    } else {
                        self.handler.on_log(format!("⏭️ [AutoConnect] Skipping {} because it is already active (state: {:?})", node_id, state)).await;
                        return;
                    }
                }

                if !super::types::peer_slot_available(&self.active_peers, &node_id) {
                    self.handler
                        .on_log(format!(
                            "🚧 [Limit] Not dialling {}: peer limit of {} already reached",
                            node_id,
                            crate::limits::max_peers()
                        ))
                        .await;
                    backoff.attempt_count = backoff.attempt_count.max(1);
                    backoff.last_attempt = std::time::Instant::now();
                    return;
                }

                if backoff.is_connected {
                    backoff.is_connected = false;
                    backoff.attempt_count = 1;
                    backoff.last_attempt = std::time::Instant::now();
                    self.handler
                        .on_log(format!(
                            "⚠️ [Backoff] Peer {} disconnected (not active). Next retry in 5s.",
                            node_id
                        ))
                        .await;
                }

                if backoff.attempt_count > 0 {
                    let cooldown = get_cooldown_duration(backoff.attempt_count);
                    if backoff.last_attempt.elapsed() < cooldown {
                        return;
                    }
                }

                if self.current_ws_tx.is_none() {
                    return;
                }

                let peer_name = self
                    .last_known_nodes
                    .get(&node_id)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| "Unknown".to_string());
                let target_nodes: Vec<&nodeinnet_p2p::NodeInfo> = self
                    .last_known_nodes
                    .values()
                    .filter(|n| n.app_type != "web" && n.id > self.my_info.id)
                    .collect();
                let mut sorted_targets = target_nodes;
                sorted_targets.sort_by(|a, b| a.id.cmp(&b.id));
                let position = sorted_targets.iter().position(|n| n.id == node_id);
                let plan_info = if let Some(pos) = position {
                    format!(" [#{}/{}]", pos + 1, sorted_targets.len())
                } else {
                    "".to_string()
                };

                self.handler
                    .on_log(format!(
                        "🔌 [AutoConnect] Initiating new WebRTC connection to {} ({}){}",
                        node_id, peer_name, plan_info
                    ))
                    .await;
                self.handler.on_p2p_connecting(node_id.clone()).await;
                self.handler
                    .on_peer_state_changed(
                        node_id.clone(),
                        crate::P2pPeerState::ConnectingTransport,
                    )
                    .await;

                backoff.attempt_count += 1;
                backoff.last_attempt = std::time::Instant::now();
                backoff.is_connected = false;

                match crate::rtc::WebRtcClient::new(
                    self.handler.clone(),
                    self.net_tx_bg.clone(),
                    self.my_info_for(&node_id, &Link::Account),
                    node_id.clone(),
                    self.private_key.clone(),
                    self.current_turn_credentials.clone(),
                    self.peer_store.clone(),
                    Link::Account,
                )
                .await
                {
                    Ok(rtc_client) => match rtc_client.create_offer().await {
                        Ok(sdp) => {
                            self.handler
                                .on_log(format!(
                                    "📄 [AutoConnect] SDP Offer created for {}. Sending...",
                                    &node_id
                                ))
                                .await;
                            let envelope = RtcSignalEnvelope {
                                to_node_id: node_id.clone(),
                                signal: RtcSignal::Offer {
                                    sdp,
                                    ice_restart: false,
                                },
                            };
                            let current_ws = self.current_ws_tx.clone();
                            let handler_route = self.handler.clone();
                            tokio::spawn(async move {
                                super::route_rtc_signal(envelope, &current_ws, &handler_route)
                                    .await;
                            });
                            self.active_peers.insert(node_id.clone(), rtc_client);
                        }
                        Err(e) => {
                            self.handler
                                .on_log(format!(
                                    "❌ [AutoConnect] Failed to create offer for {}: {}",
                                    node_id, e
                                ))
                                .await;
                            self.handler
                                .on_peer_failed(
                                    node_id.clone(),
                                    crate::P2pFailure::OfferFailed(e.to_string()),
                                )
                                .await;
                            self.handler
                                .on_peer_state_changed(
                                    node_id.clone(),
                                    crate::P2pPeerState::Disconnected,
                                )
                                .await;
                        }
                    },
                    Err(e) => {
                        self.handler
                            .on_log(format!(
                                "❌ [AutoConnect] Failed to init WebRTC client for {}: {}",
                                node_id, e
                            ))
                            .await;
                        self.handler
                            .on_peer_failed(
                                node_id.clone(),
                                crate::P2pFailure::ClientInitFailed(e.to_string()),
                            )
                            .await;
                        self.handler
                            .on_peer_state_changed(
                                node_id.clone(),
                                crate::P2pPeerState::Disconnected,
                            )
                            .await;
                    }
                }
            }
            NetCmd::Call(node_id) => {
                if let Some(peer) = self.active_peers.get(&node_id) {
                    let state = peer.peer_connection.connection_state();
                    let is_stuck = (state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::New || state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Connecting) && peer.created_at.elapsed().as_secs() > 5;
                    let is_dead = state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Disconnected || state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Failed || state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Closed;

                    if is_stuck || is_dead {
                        self.handler
                            .on_log(format!(
                                "⚠️ [Call] Peer {} is in stuck/dead state {:?}. Reaping it...",
                                node_id, state
                            ))
                            .await;
                        if let Some(peer) = self.active_peers.remove(&node_id) {
                            peer.end_session().await;
                            let pc = peer.peer_connection.clone();
                            drop(peer);
                            let _peer_id = node_id.clone();
                            tokio::spawn(async move {
                                let _ = pc.close().await;
                            });
                        }
                    } else {
                        self.handler
                            .on_log(format!(
                                "⏭️ [Call] Skipping {} because it is already active (state: {:?})",
                                node_id, state
                            ))
                            .await;
                        return;
                    }
                }

                if !super::types::peer_slot_available(&self.active_peers, &node_id) {
                    self.handler
                        .on_log(format!(
                            "🚧 [Limit] Call to {} refused: peer limit of {} already reached",
                            node_id,
                            crate::limits::max_peers()
                        ))
                        .await;
                    return;
                }

                self.focused_peer = Some(node_id.clone());

                let backoff = self
                    .backoff_states
                    .entry(node_id.clone())
                    .or_insert_with(|| PeerBackoff {
                        attempt_count: 0,
                        last_attempt: std::time::Instant::now(),
                        is_connected: false,
                    });
                backoff.attempt_count = 1;
                backoff.last_attempt = std::time::Instant::now();
                backoff.is_connected = false;

                if self.current_ws_tx.is_none() {
                    return;
                }

                let peer_name = self
                    .last_known_nodes
                    .get(&node_id)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| "Unknown".to_string());
                let target_nodes: Vec<&nodeinnet_p2p::NodeInfo> = self
                    .last_known_nodes
                    .values()
                    .filter(|n| n.app_type != "web" && n.id > self.my_info.id)
                    .collect();
                let mut sorted_targets = target_nodes;
                sorted_targets.sort_by(|a, b| a.id.cmp(&b.id));
                let position = sorted_targets.iter().position(|n| n.id == node_id);
                let plan_info = if let Some(pos) = position {
                    format!(" [#{}/{}]", pos + 1, sorted_targets.len())
                } else {
                    "".to_string()
                };

                self.handler
                    .on_log(format!(
                        "📞 [Call] Initiating call to {} ({}){}...",
                        node_id, peer_name, plan_info
                    ))
                    .await;
                self.handler.on_p2p_connecting(node_id.clone()).await;
                self.handler
                    .on_peer_state_changed(
                        node_id.clone(),
                        crate::P2pPeerState::ConnectingTransport,
                    )
                    .await;
                match crate::rtc::WebRtcClient::new(
                    self.handler.clone(),
                    self.net_tx_bg.clone(),
                    self.my_info_for(&node_id, &Link::Account),
                    node_id.clone(),
                    self.private_key.clone(),
                    self.current_turn_credentials.clone(),
                    self.peer_store.clone(),
                    Link::Account,
                )
                .await
                {
                    Ok(rtc_client) => match rtc_client.create_offer().await {
                        Ok(sdp) => {
                            self.handler
                                .on_log(format!(
                                    "📄 SDP Offer created for {}. Sending...",
                                    &node_id
                                ))
                                .await;
                            let envelope = RtcSignalEnvelope {
                                to_node_id: node_id.clone(),
                                signal: RtcSignal::Offer {
                                    sdp,
                                    ice_restart: false,
                                },
                            };
                            let current_ws = self.current_ws_tx.clone();
                            let handler_route = self.handler.clone();
                            tokio::spawn(async move {
                                super::route_rtc_signal(envelope, &current_ws, &handler_route)
                                    .await;
                            });
                            self.active_peers.insert(node_id.clone(), rtc_client);
                        }
                        Err(e) => {
                            self.handler
                                .on_log(format!("❌ Failed to create offer: {}", e))
                                .await;
                        }
                    },
                    Err(e) => {
                        self.handler
                            .on_log(format!("❌ Failed to init WebRTC: {}", e))
                            .await;
                    }
                }
            }
            _ => {}
        }
    }
}
