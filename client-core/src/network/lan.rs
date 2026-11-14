use super::manager::NetworkManager;
use crate::{LanCmd, NetCmd};
use nodeinnet_p2p::rtc::{InboundRtcSignal, RtcSignal, RtcSignalEnvelope};
use nodeinnet_p2p::{NodeInfo, ResourceType, SharedResource};
use p2p_node::lan::{Grants, Lan, LanConfig, LanEvent, LanSignal, Link, PairOutcome, Visibility};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc as tokio_mpsc;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as State;
use webrtc::peer_connection::signaling_state::RTCSignalingState;

const STUCK_SECS: u64 = 20;

impl NetworkManager {
    pub async fn start_lan(
        &mut self,
        mut config: LanConfig,
        signals: tokio_mpsc::Sender<LanSignal>,
    ) -> bool {
        self.lan_resources = std::mem::take(&mut config.resources);
        match Lan::start(config, &self.private_key, signals).await {
            Ok(lan) => {
                let nodes: Vec<NodeInfo> = self.last_known_nodes.values().cloned().collect();
                lan.set_account_nodes(&nodes);
                self.lan = Some(lan);
                true
            }
            Err(e) => {
                self.handler
                    .on_log(format!("❌ [LAN] Could not start: {}", e))
                    .await;
                self.handler
                    .on_lan_event(LanEvent::Failed(e.to_string()))
                    .await;
                false
            }
        }
    }

    pub fn my_info_for(&self, id: &str, link: &Link) -> NodeInfo {
        let Link::Lan { .. } = link else {
            return self.my_info.clone();
        };
        let Some(lan) = &self.lan else {
            return NodeInfo {
                resources: Vec::new(),
                ..self.my_info.clone()
            };
        };
        let grants = match lan.visibility() {
            Visibility::Off => None,
            Visibility::TrustedOnly | Visibility::Open => lan.grants(id),
        };
        lan_info(&self.my_info, lan.id(), &self.lan_resources, grants)
    }

    pub fn lan_admits_session(&self, id: &str) -> bool {
        self.lan
            .as_ref()
            .is_some_and(|lan| lan.visibility() != Visibility::Off && lan.grants(id).is_some())
    }

    pub fn lan_offer_stands(&self, id: &str) -> bool {
        self.active_peers.get(id).is_some_and(|peer| {
            peer.peer_connection.signaling_state() == RTCSignalingState::HaveLocalOffer
        }) && self.lan.as_ref().is_some_and(|lan| lan.id() > id)
    }

    pub fn lan_knows(&self, id: &str) -> bool {
        self.lan.as_ref().is_some_and(|lan| lan.knows(id))
    }

    pub async fn handle_lan_cmd(&mut self, cmd: LanCmd) {
        let Some(lan) = self.lan.clone() else {
            let off = "the local network is off".to_string();
            match cmd {
                LanCmd::Open(id) => self.open_failed(id, off).await,
                LanCmd::Pair(id) => {
                    self.handler
                        .on_lan_event(LanEvent::PairDone {
                            id,
                            outcome: PairOutcome::Failed(off),
                        })
                        .await;
                }
                _ => {
                    self.handler
                        .on_log("⚠️ [LAN] Not running; command ignored".to_string())
                        .await;
                }
            }
            return;
        };
        match cmd {
            LanCmd::SetVisibility(visibility) => {
                let was_off = lan.visibility() == Visibility::Off;
                lan.set_visibility(visibility);
                if was_off != (visibility == Visibility::Off) {
                    self.end_trusted_lan_sessions(&lan).await;
                }
            }
            LanCmd::Browse(on) => lan.browse(on),
            LanCmd::SetResources(resources) => {
                self.lan_resources = resources;
                self.end_trusted_lan_sessions(&lan).await;
            }
            LanCmd::Open(id) => self.open_lan(&lan, id).await,
            LanCmd::Pair(id) => lan.pair(&id),
            LanCmd::ConfirmPair(id, code) => lan.confirm_pair(&id, &code),
            LanCmd::CancelPair(id) => lan.cancel_pair(&id),
            LanCmd::Forget(id) => {
                lan.forget(&id);
                self.end_lan_session(&id).await;
            }
            LanCmd::Block(id) => {
                lan.block(&id);
                self.end_lan_session(&id).await;
            }
            LanCmd::Unblock(id) => lan.unblock(&id),
            LanCmd::SetGrants(id, grants) => {
                if lan.set_grants(&id, grants) {
                    self.end_lan_session(&id).await;
                }
            }
            LanCmd::ResumePairing => lan.resume_pairing(),
        }
    }

    pub async fn handle_lan_signal(&mut self, signal: LanSignal) {
        match signal {
            LanSignal::Rtc { id, key, signal } => {
                let inbound = InboundRtcSignal {
                    from_node_id: id,
                    signal,
                };
                self.handle_peer_cmd(NetCmd::HandleInboundSignal(inbound, Link::Lan { key }))
                    .await;
            }
            LanSignal::Close { id } => self.end_lan_session(&id).await,
            LanSignal::Unreachable { id, dial, reason } => {
                if self.lan_dials.get(&id) != Some(&dial) {
                    return;
                }
                self.lan_dials.remove(&id);
                let unanswered = self.active_peers.get(&id).is_some_and(|peer| {
                    peer.link != Link::Account
                        && !peer.node_context.session_up.load(Ordering::SeqCst)
                });
                if unanswered {
                    self.end_lan_session(&id).await;
                }
                self.open_failed(id, reason).await;
            }
            LanSignal::Prompt(prompt, reply) => self.handler.on_pair_request(prompt, reply).await,
            LanSignal::Event(event) => self.handler.on_lan_event(event).await,
            LanSignal::Log(line) => self.handler.on_log(line).await,
        }
    }

    pub async fn handle_lan_session_up(
        &mut self,
        id: String,
        connection_id: uuid::Uuid,
        resources: Vec<SharedResource>,
    ) {
        let live = self
            .active_peers
            .get(&id)
            .is_some_and(|peer| peer.link != Link::Account && peer.connection_id == connection_id);
        if !live {
            self.handler
                .on_log(format!(
                    "⏭️ [LAN] Ignoring a stale session notice for {}",
                    id
                ))
                .await;
            return;
        }
        self.lan_dials.remove(&id);
        self.handler
            .on_log(format!(
                "✨ [LAN] Session with {} is up ({} resource(s))",
                id,
                resources.len()
            ))
            .await;
        if let Some(lan) = &self.lan {
            lan.session(&id, Some(resources));
        }
    }

    pub async fn send_lan_signal(&self, id: &str, signal: RtcSignal) {
        if !self
            .lan
            .as_ref()
            .is_some_and(|lan| lan.send_rtc(id, signal))
        {
            self.handler
                .on_log(format!("⚠️ [LAN] No tunnel to {}; signal dropped", id))
                .await;
        }
    }

    pub async fn send_signal(&self, link: Link, to_node_id: String, signal: RtcSignal) {
        match link {
            Link::Account => {
                let envelope = RtcSignalEnvelope { to_node_id, signal };
                let current_ws = self.current_ws_tx.clone();
                let handler = self.handler.clone();
                tokio::spawn(async move {
                    super::route_rtc_signal(envelope, &current_ws, &handler).await;
                });
            }
            Link::Lan { .. } => self.send_lan_signal(&to_node_id, signal).await,
        }
    }

    async fn open_lan(&mut self, lan: &Arc<Lan>, id: String) {
        if let Some(peer) = self.active_peers.get(&id) {
            if peer.link == Link::Account {
                self.open_failed(id, "it has a session through the account".to_string())
                    .await;
                return;
            }
            let state = peer.peer_connection.connection_state();
            let stuck = matches!(state, State::New | State::Connecting)
                && peer.created_at.elapsed().as_secs() > 5;
            let dead = matches!(state, State::Disconnected | State::Failed | State::Closed);
            if !stuck && !dead {
                self.handler
                    .on_log(format!("⏭️ [LAN] {} is already open ({:?})", id, state))
                    .await;
                return;
            }
            self.end_lan_session(&id).await;
        }
        if !super::types::peer_slot_available(&self.active_peers, &id) {
            let reason = format!(
                "the limit of {} peers is reached",
                crate::limits::max_peers()
            );
            self.open_failed(id, reason).await;
            return;
        }
        let Some(opened) = lan.open(&id) else {
            self.open_failed(id, "not paired; pair it first".to_string())
                .await;
            return;
        };
        let link = Link::Lan { key: opened.key };
        self.handler.on_p2p_connecting(id.clone()).await;
        self.handler
            .on_peer_state_changed(id.clone(), crate::P2pPeerState::ConnectingTransport)
            .await;
        let offered = match crate::rtc::WebRtcClient::new(
            self.handler.clone(),
            self.net_tx_bg.clone(),
            self.my_info_for(&id, &link),
            id.clone(),
            self.private_key.clone(),
            None,
            self.peer_store.clone(),
            link,
        )
        .await
        {
            Ok(client) => match client.create_offer().await {
                Ok(sdp) => Ok((client, sdp)),
                Err(e) => Err(crate::P2pFailure::OfferFailed(e.to_string())),
            },
            Err(e) => Err(crate::P2pFailure::ClientInitFailed(e.to_string())),
        };
        match offered {
            Ok((client, sdp)) => {
                self.active_peers.insert(id.clone(), client);
                if opened.dial != 0 {
                    self.lan_dials.insert(id.clone(), opened.dial);
                }
                let offer = RtcSignal::Offer {
                    sdp,
                    ice_restart: false,
                };
                self.send_lan_signal(&id, offer).await;
            }
            Err(failure) => {
                lan.session(&id, None);
                self.handler
                    .on_peer_failed(id.clone(), failure.clone())
                    .await;
                self.handler
                    .on_peer_state_changed(id.clone(), crate::P2pPeerState::Disconnected)
                    .await;
                self.open_failed(id, failure.to_string()).await;
            }
        }
    }

    async fn open_failed(&self, id: String, reason: String) {
        self.handler
            .on_lan_event(LanEvent::OpenFailed { id, reason })
            .await;
    }

    pub async fn end_lan_session(&mut self, id: &str) {
        if !self
            .active_peers
            .get(id)
            .is_some_and(|peer| peer.link != Link::Account)
        {
            return;
        }
        self.lan_dials.remove(id);
        if let Some(peer) = self.active_peers.remove(id) {
            self.handler
                .on_log(format!("🔴 [LAN] Ended the session with {}", id))
                .await;
            peer.end_session().await;
            let pc = peer.peer_connection.clone();
            drop(peer);
            let handler = self.handler.clone();
            let id = id.to_string();
            tokio::spawn(async move {
                let _ = pc.close().await;
                handler.on_p2p_disconnected(id).await;
            });
        }
        if self.focused_peer.as_deref() == Some(id) {
            self.focused_peer = None;
        }
        if let Some(lan) = &self.lan {
            lan.session(id, None);
        }
    }

    async fn end_trusted_lan_sessions(&mut self, lan: &Arc<Lan>) {
        let trusted: Vec<String> = self
            .active_peers
            .iter()
            .filter(|(id, peer)| peer.link != Link::Account && lan.grants(id).is_some())
            .map(|(id, _)| id.clone())
            .collect();
        for id in trusted {
            self.end_lan_session(&id).await;
        }
    }

    pub async fn reap_stuck_lan_sessions(&mut self) {
        let Some(lan) = self.lan.clone() else {
            return;
        };
        let stuck: Vec<(String, bool)> = self
            .active_peers
            .iter()
            .filter(|(id, peer)| {
                peer.link != Link::Account
                    && matches!(
                        peer.peer_connection.connection_state(),
                        State::New | State::Connecting
                    )
                    && peer.created_at.elapsed().as_secs() > STUCK_SECS
                    && !peer.node_context.session_up.load(Ordering::SeqCst)
                    && !lan.dialing(id)
            })
            .map(|(id, peer)| {
                let offered =
                    peer.peer_connection.signaling_state() == RTCSignalingState::HaveLocalOffer;
                (id.clone(), offered)
            })
            .collect();
        for (id, offered) in stuck {
            self.end_lan_session(&id).await;
            if offered {
                self.open_failed(id, "the device did not answer".to_string())
                    .await;
            }
        }
    }
}

fn lan_info(
    my_info: &NodeInfo,
    me: &str,
    shared: &[SharedResource],
    grants: Option<Grants>,
) -> NodeInfo {
    let mut resources: Vec<SharedResource> = Vec::new();
    if let Some(grants) = grants {
        for resource in shared {
            let granted = match resource.resource_type {
                ResourceType::Filesystem => true,
                ResourceType::Terminal => grants.terminal,
                _ => false,
            };
            let id = resource_id(&resource.resource_type, me)
                .filter(|id| granted && !resources.iter().any(|kept| kept.id == *id));
            if let Some(id) = id {
                resources.push(SharedResource {
                    id,
                    session_token: None,
                    ..resource.clone()
                });
            }
        }
    }
    NodeInfo {
        id: me.to_string(),
        resources,
        ..my_info.clone()
    }
}

pub(crate) fn resource_id(resource_type: &ResourceType, owner: &str) -> Option<String> {
    nodeinnet_p2p::resource_id_base(resource_type).map(|base| format!("{}-{}", base, owner))
}

pub(crate) fn served_over_lan(resource: &SharedResource, owner: &str) -> bool {
    matches!(
        resource.resource_type,
        ResourceType::Filesystem | ResourceType::Terminal
    ) && resource_id(&resource.resource_type, owner).is_some_and(|id| id == resource.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppEventHandler;
    use nodeinnet_p2p::P2pMessage;
    use std::io;
    use std::sync::Mutex;

    const ME: &str = "0123456789abcdef0123456789abcdef";
    const SHARES: &str = r#"{"shares":[{"name":"Share","path":"/srv/share"}]}"#;

    fn shared(id: &str, resource_type: ResourceType, config: Option<&str>) -> SharedResource {
        SharedResource {
            id: id.to_string(),
            name: id.to_string(),
            resource_type,
            config: config.map(str::to_string),
            is_active: true,
            session_token: Some("stale".to_string()),
        }
    }

    fn me() -> NodeInfo {
        NodeInfo {
            id: "account-id".to_string(),
            name: "me".to_string(),
            os: "linux".to_string(),
            version: "0.0.0".to_string(),
            app_type: "test".to_string(),
            build_type: "debug".to_string(),
            public_key: "key".to_string(),
            resources: vec![shared("fs-account-id", ResourceType::Filesystem, None)],
            is_online: true,
            last_used: 0,
            is_temporary: false,
        }
    }

    fn offered() -> Vec<SharedResource> {
        vec![
            shared("files", ResourceType::Filesystem, Some(SHARES)),
            shared("shell", ResourceType::Terminal, None),
            shared("more-files", ResourceType::Filesystem, None),
            shared("sysinfo", ResourceType::SystemInfo, None),
            shared(
                "6f1c2a3e-0000-4000-8000-000000000000",
                ResourceType::SyncFolder,
                None,
            ),
        ]
    }

    fn ids(info: &NodeInfo) -> Vec<&str> {
        info.resources.iter().map(|r| r.id.as_str()).collect()
    }

    #[test]
    fn a_device_that_is_not_trusted_gets_nothing() {
        let info = lan_info(&me(), ME, &offered(), None);
        assert_eq!(info.id, ME);
        assert!(info.resources.is_empty());
    }

    #[test]
    fn a_trusted_device_gets_the_shares_under_my_lan_id() {
        let info = lan_info(&me(), ME, &offered(), Some(Grants::default()));
        assert_eq!(ids(&info), [format!("fs-{ME}")]);
        assert_eq!(info.resources[0].config.as_deref(), Some(SHARES));
        assert_eq!(info.resources[0].session_token, None);
        assert_eq!(info.public_key, "key");
    }

    #[test]
    fn the_terminal_needs_its_grant() {
        let info = lan_info(&me(), ME, &offered(), Some(Grants { terminal: true }));
        assert_eq!(ids(&info), [format!("fs-{ME}"), format!("terminal-{ME}")]);
    }

    #[test]
    fn a_lan_resource_id_names_its_owner() {
        assert_eq!(
            resource_id(&ResourceType::Filesystem, ME),
            Some(format!("fs-{ME}"))
        );
        assert_eq!(resource_id(&ResourceType::SyncFolder, ME), None);
    }

    #[test]
    fn only_files_and_the_terminal_are_taken_over_lan() {
        let other = "f".repeat(32);
        let kept = [
            shared(&format!("fs-{ME}"), ResourceType::Filesystem, None),
            shared(&format!("terminal-{ME}"), ResourceType::Terminal, None),
        ];
        for resource in &kept {
            assert!(served_over_lan(resource, ME), "{}", resource.id);
        }
        let dropped = [
            shared(&format!("desktop-{ME}"), ResourceType::RemoteDesktop, None),
            shared(&format!("fs-{other}"), ResourceType::Filesystem, None),
            shared("b-scratch", ResourceType::Filesystem, None),
            shared(&format!("sync-{ME}"), ResourceType::SyncFolder, None),
        ];
        for resource in &dropped {
            assert!(!served_over_lan(resource, ME), "{}", resource.id);
        }
    }

    struct Quiet;

    #[async_trait::async_trait]
    impl AppEventHandler for Quiet {
        async fn on_log(&self, _msg: String) {}
        async fn on_connected(&self) {}
        async fn on_disconnected(&self) {}
        async fn on_update_nodes(&self, _nodes: Vec<NodeInfo>) {}
        async fn on_download_complete(&self, _path: std::path::PathBuf) {}
        async fn on_p2p_message(&self, _msg: P2pMessage) {}
        async fn on_p2p_connected(&self, _peer_id: String) {}
        async fn on_p2p_disconnected(&self, _peer_id: String) {}
    }

    #[derive(Default)]
    struct Memory(Mutex<Option<String>>);

    impl p2p_node::lan::TrustStore for Memory {
        fn load(&self) -> io::Result<Option<String>> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn save(&self, doc: &str) -> io::Result<()> {
            *self.0.lock().unwrap() = Some(doc.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn forget_ends_the_lan_session_at_once() {
        let handler: Arc<dyn AppEventHandler> = Arc::new(Quiet);
        let (net_tx, _net_rx) = tokio_mpsc::unbounded_channel();
        let store: Arc<dyn nodeinnet_p2p::PeerStore> =
            Arc::new(nodeinnet_p2p::MemoryPeerStore::default());
        let (private_key, _) = nodeinnet_p2p::crypto::generate_ed25519_keypair();
        let mut manager = NetworkManager::new(
            me(),
            private_key,
            handler.clone(),
            net_tx.clone(),
            store.clone(),
        );
        let (lan_tx, _lan_rx) = tokio_mpsc::channel(256);
        let config = LanConfig {
            name: "me".to_string(),
            os: "linux".to_string(),
            kind: "desktop".to_string(),
            visibility: Visibility::Off,
            browse: false,
            port: 0,
            resources: offered(),
            trust: Arc::new(Memory::default()),
            test_mode: true,
        };
        assert!(manager.start_lan(config, lan_tx).await);

        let id = "ab".repeat(16);
        let link = Link::Lan { key: [9; 32] };
        let client = crate::rtc::WebRtcClient::new(
            handler,
            net_tx,
            manager.my_info_for(&id, &link),
            id.clone(),
            String::new(),
            None,
            store,
            link,
        )
        .await
        .expect("a peer connection");
        manager.active_peers.insert(id.clone(), client);

        manager.handle_lan_cmd(LanCmd::Forget(id.clone())).await;
        assert!(!manager.active_peers.contains_key(&id));

        manager
            .handle_lan_signal(LanSignal::Rtc {
                id: id.clone(),
                key: [9; 32],
                signal: RtcSignal::Offer {
                    sdp: "v=0".to_string(),
                    ice_restart: true,
                },
            })
            .await;
        assert!(!manager.active_peers.contains_key(&id));

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn a_session_that_came_up_is_not_reaped() {
        let handler: Arc<dyn AppEventHandler> = Arc::new(Quiet);
        let (net_tx, _net_rx) = tokio_mpsc::unbounded_channel();
        let store: Arc<dyn nodeinnet_p2p::PeerStore> =
            Arc::new(nodeinnet_p2p::MemoryPeerStore::default());
        let (private_key, _) = nodeinnet_p2p::crypto::generate_ed25519_keypair();
        let mut manager = NetworkManager::new(
            me(),
            private_key,
            handler.clone(),
            net_tx.clone(),
            store.clone(),
        );
        let (lan_tx, _lan_rx) = tokio_mpsc::channel(256);
        let config = LanConfig {
            name: "me".to_string(),
            os: "linux".to_string(),
            kind: "desktop".to_string(),
            visibility: Visibility::Off,
            browse: false,
            port: 0,
            resources: offered(),
            trust: Arc::new(Memory::default()),
            test_mode: true,
        };
        assert!(manager.start_lan(config, lan_tx).await);

        let (up, never) = ("ab".repeat(16), "cd".repeat(16));
        for (id, came_up) in [(&up, true), (&never, false)] {
            let link = Link::Lan { key: [9; 32] };
            let mut client = crate::rtc::WebRtcClient::new(
                handler.clone(),
                net_tx.clone(),
                manager.my_info_for(id, &link),
                id.clone(),
                String::new(),
                None,
                store.clone(),
                link,
            )
            .await
            .expect("a peer connection");
            client.created_at = std::time::Instant::now() - std::time::Duration::from_secs(30);
            client
                .node_context
                .session_up
                .store(came_up, Ordering::SeqCst);
            manager.active_peers.insert(id.clone(), client);
        }

        manager.reap_stuck_lan_sessions().await;
        assert!(manager.active_peers.contains_key(&up));
        assert!(!manager.active_peers.contains_key(&never));

        manager.shutdown().await;
    }
}
