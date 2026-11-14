use super::{IncomingP2pContext, handle_incoming_p2p_message, signal_cmd};
use crate::{AppEventHandler, NetCmd, P2pFailure, P2pPeerState};
use nodeinnet_p2p::crypto::{generate_ed25519_keypair, generate_session_token};
use nodeinnet_p2p::rtc::RtcSignal;
use nodeinnet_p2p::{
    MemoryPeerStore, NodeInfo, OutboundP2pPayload, P2pMessage, PeerStore, ResourceType,
    SecuredP2pEnvelope, SharedResource, WsMessage,
};
use p2p_node::NodeContext;
use p2p_node::lan::Link;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::{Mutex, mpsc};
use webrtc::api::APIBuilder;
use webrtc::peer_connection::configuration::RTCConfiguration;

#[derive(Default)]
struct Seen {
    messages: Mutex<Vec<P2pMessage>>,
    states: Mutex<Vec<P2pPeerState>>,
    failures: Mutex<Vec<P2pFailure>>,
    connected: AtomicUsize,
}

struct Recorder(Arc<Seen>);

#[async_trait::async_trait]
impl AppEventHandler for Recorder {
    async fn on_log(&self, _msg: String) {}
    async fn on_connected(&self) {}
    async fn on_disconnected(&self) {}
    async fn on_update_nodes(&self, _nodes: Vec<NodeInfo>) {}
    async fn on_download_complete(&self, _path: std::path::PathBuf) {}
    async fn on_p2p_message(&self, msg: P2pMessage) {
        self.0.messages.lock().await.push(msg);
    }
    async fn on_p2p_connected(&self, _peer_id: String) {
        self.0.connected.fetch_add(1, Ordering::SeqCst);
    }
    async fn on_p2p_disconnected(&self, _peer_id: String) {}
    async fn on_peer_state_changed(&self, _peer_id: String, state: P2pPeerState) {
        self.0.states.lock().await.push(state);
    }
    async fn on_peer_failed(&self, _peer_id: String, failure: P2pFailure) {
        self.0.failures.lock().await.push(failure);
    }
}

fn node(id: &str, public_key: &str, resources: Vec<SharedResource>) -> NodeInfo {
    NodeInfo {
        id: id.to_string(),
        name: id.to_string(),
        os: "test".to_string(),
        version: "0.0.0".to_string(),
        app_type: "test".to_string(),
        build_type: "debug".to_string(),
        public_key: public_key.to_string(),
        resources,
        is_online: true,
        last_used: 0,
        is_temporary: false,
    }
}

fn resource(id: &str, resource_type: ResourceType, token: Option<String>) -> SharedResource {
    SharedResource {
        id: id.to_string(),
        name: id.to_string(),
        resource_type,
        config: None,
        is_active: true,
        session_token: token,
    }
}

fn signed(token: &str, message: &P2pMessage) -> Option<String> {
    let bytes = nodeinnet_p2p::p2p::to_bson_vec(message).expect("bson");
    Some(nodeinnet_p2p::crypto::compute_hmac_sha256(&bytes, token))
}

fn listing(resource_id: &str) -> P2pMessage {
    P2pMessage::RequestEntries {
        request_id: uuid::Uuid::new_v4(),
        resource_id: resource_id.to_string(),
        path: "/".to_string(),
    }
}

struct Session {
    ctx: IncomingP2pContext,
    seen: Arc<Seen>,
    out_rx: mpsc::Receiver<OutboundP2pPayload>,
    net_rx: mpsc::UnboundedReceiver<NetCmd>,
    store: Arc<MemoryPeerStore>,
    my_id: String,
    peer_id: String,
    peer_key: String,
}

async fn open(my_resources: Vec<SharedResource>) -> Session {
    let my_id = uuid::Uuid::new_v4().to_string();
    let peer_id = uuid::Uuid::new_v4().to_string();
    let (peer_key, peer_public) = generate_ed25519_keypair();
    nodeinnet_p2p::update_known_public_keys(&[node(&peer_id, &peer_public, vec![])]);

    let (out_tx, out_rx) = mpsc::channel(64);
    let (log_tx, _) = mpsc::channel(64);
    let (event_tx, _) = mpsc::channel(8);
    let store = Arc::new(MemoryPeerStore::default());
    let node_context = NodeContext::new(
        out_tx,
        log_tx,
        event_tx,
        node(&my_id, "", my_resources),
        peer_id.clone(),
        store.clone(),
    );
    let peer_connection = Arc::new(
        APIBuilder::new()
            .build()
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    let dc = peer_connection
        .create_data_channel("gate", None)
        .await
        .expect("data channel");
    let (net_tx, net_rx) = mpsc::unbounded_channel();
    let seen = Arc::new(Seen::default());
    Session {
        ctx: IncomingP2pContext {
            handler: Arc::new(Recorder(seen.clone())),
            dc,
            node_context,
            target_node_id: peer_id.clone(),
            last_pong: Arc::new(AtomicU64::new(0)),
            net_tx,
            peer_connection,
            connection_id: uuid::Uuid::new_v4(),
        },
        seen,
        out_rx,
        net_rx,
        store,
        my_id,
        peer_id,
        peer_key,
    }
}

impl Session {
    async fn deliver(&self, mac: Option<String>, message: P2pMessage) {
        let bytes =
            nodeinnet_p2p::p2p::to_bson_vec(&SecuredP2pEnvelope { mac, message }).expect("bson");
        handle_incoming_p2p_message(&bytes, self.ctx.clone()).await;
    }

    fn handshake(&self, signing_key: &str) -> P2pMessage {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.handshake_at(signing_key, ts)
    }

    fn handshake_at(&self, signing_key: &str, ts: u64) -> P2pMessage {
        P2pMessage::Handshake {
            node_version: "0.0.0".to_string(),
            timestamp_ms: ts,
            signature: nodeinnet_p2p::crypto::sign_p2p_handshake(
                signing_key,
                &self.peer_id,
                &self.my_id,
                ts,
            )
            .expect("sign"),
            requested_resources: None,
            max_chunk_size: Some(10240),
            local_tcp_port: None,
            from_node_id: Some(self.peer_id.clone()),
        }
    }

    async fn verified_handshake(&self) {
        self.deliver(None, self.handshake(&self.peer_key)).await;
    }

    fn authenticated(&self) -> bool {
        self.ctx
            .node_context
            .is_authenticated
            .load(Ordering::SeqCst)
    }

    async fn key(&self, id: &str) -> Option<String> {
        self.ctx
            .node_context
            .session_keys
            .lock()
            .await
            .get(id)
            .cloned()
    }

    fn sent_handshake_responses(&mut self) -> Vec<Vec<SharedResource>> {
        let mut sent = Vec::new();
        while let Ok(payload) = self.out_rx.try_recv() {
            if let OutboundP2pPayload::Message(SecuredP2pEnvelope {
                message: P2pMessage::HandshakeResponse { resources },
                ..
            }) = payload
            {
                sent.push(resources);
            }
        }
        sent
    }

    fn peer_connected(&mut self) -> Vec<Vec<SharedResource>> {
        let mut announced = Vec::new();
        while let Ok(cmd) = self.net_rx.try_recv() {
            if let NetCmd::PeerConnected(_, resources) = cmd {
                announced.push(resources);
            }
        }
        announced
    }

    fn lan_session_up(&mut self) -> Vec<Vec<SharedResource>> {
        let mut announced = Vec::new();
        while let Ok(cmd) = self.net_rx.try_recv() {
            match cmd {
                NetCmd::LanSessionUp(_, connection_id, resources) => {
                    assert_eq!(connection_id, self.ctx.connection_id);
                    announced.push(resources);
                }
                NetCmd::PeerConnected(..) => {
                    panic!("a LAN session was announced as an account one")
                }
                _ => {}
            }
        }
        announced
    }

    async fn connected_states(&self) -> usize {
        self.seen
            .states
            .lock()
            .await
            .iter()
            .filter(|state| **state == P2pPeerState::Connected)
            .count()
    }
}

async fn open_lan(my_resources: Vec<SharedResource>) -> (Session, String) {
    let mut s = open(my_resources).await;
    let (private, public) = generate_ed25519_keypair();
    let key = p2p_node::lan::id::key_bytes(&public).expect("a 32-byte key");
    s.ctx.node_context.link = Link::Lan { key };
    let account_key = std::mem::replace(&mut s.peer_key, private);
    (s, account_key)
}

fn token_of(sent: &[Vec<SharedResource>], id: &str) -> String {
    sent.last()
        .and_then(|resources| resources.iter().find(|r| r.id == id))
        .and_then(|r| r.session_token.clone())
        .expect("a token minted for my resource")
}

#[tokio::test]
async fn a_forged_handshake_response_gives_no_tokens_and_no_session() {
    let mut s = open(vec![resource("fs-mine", ResourceType::Filesystem, None)]).await;
    let forged = generate_session_token();
    s.deliver(
        None,
        P2pMessage::HandshakeResponse {
            resources: vec![
                resource("fs-mine", ResourceType::Filesystem, Some(forged.clone())),
                resource(
                    "fs-theirs",
                    ResourceType::Filesystem,
                    Some(generate_session_token()),
                ),
            ],
        },
    )
    .await;

    assert!(
        !s.authenticated(),
        "a HandshakeResponse authenticated the peer"
    );
    assert_eq!(
        s.key("fs-mine").await,
        None,
        "the peer wrote my resource's token"
    );
    assert!(s.key("fs-theirs").await.is_some());
    assert!(s.peer_connected().is_empty());
    assert_eq!(s.connected_states().await, 0);

    let request = listing("fs-mine");
    s.deliver(signed(&forged, &request), request).await;
    assert!(s.seen.messages.lock().await.is_empty());
    assert!(matches!(
        s.seen.failures.lock().await.as_slice(),
        [P2pFailure::NoSessionKey { resource }] if resource == "fs-mine"
    ));
    assert!(s.sent_handshake_responses().is_empty());
}

#[tokio::test]
async fn a_bad_signature_gets_no_handshake_response() {
    let mut s = open(vec![resource("fs-mine", ResourceType::Filesystem, None)]).await;
    let (stranger, _) = generate_ed25519_keypair();
    s.deliver(None, s.handshake(&stranger)).await;

    assert!(!s.authenticated());
    assert!(
        s.sent_handshake_responses().is_empty(),
        "tokens went to an unverified peer"
    );
    assert_eq!(s.key("fs-mine").await, None);
    assert_eq!(s.seen.connected.load(Ordering::SeqCst), 0);
    assert!(
        s.seen.messages.lock().await.is_empty(),
        "the app saw an unverified Handshake"
    );
    assert!(matches!(
        s.seen.failures.lock().await.as_slice(),
        [P2pFailure::BadSignature(_)]
    ));
}

#[tokio::test]
async fn a_token_sent_under_my_resource_id_is_ignored() {
    let mut s = open(vec![resource("fs-mine", ResourceType::Filesystem, None)]).await;
    let forged = generate_session_token();
    let forged_response = P2pMessage::HandshakeResponse {
        resources: vec![resource(
            "fs-mine",
            ResourceType::Filesystem,
            Some(forged.clone()),
        )],
    };
    s.deliver(None, forged_response.clone()).await;
    s.verified_handshake().await;

    let sent = s.sent_handshake_responses();
    assert_eq!(sent.len(), 1);
    let minted = token_of(&sent, "fs-mine");
    assert_ne!(minted, forged);
    s.deliver(None, forged_response).await;
    assert_eq!(s.key("fs-mine").await, Some(minted.clone()));

    let request = listing("fs-mine");
    s.deliver(signed(&forged, &request), request).await;
    assert!(s.seen.messages.lock().await.is_empty());
    assert!(matches!(
        s.seen.failures.lock().await.as_slice(),
        [P2pFailure::BadHmac { resource }] if resource == "fs-mine"
    ));

    let request = listing("fs-mine");
    s.deliver(signed(&minted, &request), request).await;
    assert!(matches!(
        s.seen.messages.lock().await.as_slice(),
        [P2pMessage::RequestEntries { .. }]
    ));
}

#[tokio::test]
async fn a_handshake_response_before_the_handshake_still_opens_one_session() {
    let mut s = open(vec![resource("fs-mine", ResourceType::Filesystem, None)]).await;
    let theirs = generate_session_token();
    let response = P2pMessage::HandshakeResponse {
        resources: vec![resource(
            "fs-theirs",
            ResourceType::Filesystem,
            Some(theirs.clone()),
        )],
    };
    s.deliver(None, response.clone()).await;
    assert!(s.peer_connected().is_empty());
    assert_eq!(s.connected_states().await, 0);

    s.verified_handshake().await;
    s.deliver(None, response).await;

    let announced = s.peer_connected();
    assert_eq!(announced.len(), 1, "one PeerConnected per session");
    assert_eq!(announced[0].len(), 1);
    assert_eq!(announced[0][0].id, "fs-theirs");
    assert_eq!(announced[0][0].session_token, None);
    assert_eq!(s.connected_states().await, 1);
    assert_eq!(s.seen.connected.load(Ordering::SeqCst), 1);
    let minted = token_of(&s.sent_handshake_responses(), "fs-mine");

    let answer = P2pMessage::EntriesResponse {
        request_id: uuid::Uuid::new_v4(),
        resource_id: "fs-theirs".to_string(),
        path: "/".to_string(),
        directories: vec![],
        files: vec![],
        directories_with_dates: None,
        files_with_dates: None,
        directories_permissions: None,
        files_permissions: None,
    };
    s.deliver(signed(&theirs, &answer), answer).await;
    let request = listing("fs-mine");
    s.deliver(signed(&minted, &request), request).await;
    assert!(matches!(
        s.seen.messages.lock().await.as_slice(),
        [
            P2pMessage::EntriesResponse { .. },
            P2pMessage::RequestEntries { .. }
        ]
    ));
    assert!(s.seen.failures.lock().await.is_empty());
}

#[tokio::test]
async fn the_handshake_before_the_response_also_opens_one_session() {
    let mut s = open(vec![resource("fs-mine", ResourceType::Filesystem, None)]).await;
    s.verified_handshake().await;
    assert!(s.authenticated());
    assert!(
        s.peer_connected().is_empty(),
        "connected before the peer's tokens arrived"
    );

    s.deliver(
        None,
        P2pMessage::HandshakeResponse {
            resources: vec![resource(
                "fs-theirs",
                ResourceType::Filesystem,
                Some(generate_session_token()),
            )],
        },
    )
    .await;
    s.verified_handshake().await;

    assert_eq!(s.peer_connected().len(), 1);
    assert_eq!(s.connected_states().await, 1);
    assert_eq!(s.seen.connected.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn peers_sync_from_a_verified_peer_changes_nothing() {
    let mut s = open(vec![]).await;
    s.verified_handshake().await;
    let stranger = uuid::Uuid::new_v4().to_string();
    s.deliver(
        None,
        P2pMessage::PeersSync {
            nodes: vec![node(&stranger, "injected", vec![])],
            addresses: std::collections::HashMap::from([(
                stranger.clone(),
                vec!["192.0.2.1:8308".to_string()],
            )]),
        },
    )
    .await;

    assert_eq!(nodeinnet_p2p::get_known_public_key(&stranger), None);
    assert!(s.store.load().is_empty());
    assert!(s.net_rx.try_recv().is_err());
    assert!(s.seen.messages.lock().await.is_empty());
}

#[tokio::test]
async fn a_peers_sync_before_the_handshake_is_dropped_without_a_failure() {
    let s = open(vec![]).await;
    let stranger = uuid::Uuid::new_v4().to_string();
    s.deliver(
        None,
        P2pMessage::PeersSync {
            nodes: vec![node(&stranger, "injected", vec![])],
            addresses: std::collections::HashMap::new(),
        },
    )
    .await;

    assert_eq!(nodeinnet_p2p::get_known_public_key(&stranger), None);
    assert!(s.seen.failures.lock().await.is_empty());
    assert!(s.seen.states.lock().await.is_empty());
}

#[tokio::test]
async fn a_lan_handshake_needs_the_pinned_key_and_no_clock() {
    let (mut s, account_key) =
        open_lan(vec![resource("fs-mine", ResourceType::Filesystem, None)]).await;

    s.deliver(None, s.handshake(&account_key)).await;
    assert!(!s.authenticated(), "a LAN session used the account key");
    assert!(matches!(
        s.seen.failures.lock().await.as_slice(),
        [P2pFailure::BadSignature(_)]
    ));

    s.deliver(None, s.handshake_at(&s.peer_key, 1)).await;
    assert!(s.authenticated(), "a LAN session applied the clock rule");
    assert_eq!(s.sent_handshake_responses().len(), 1);
}

#[tokio::test]
async fn a_lan_handshake_response_keeps_only_the_senders_ids() {
    let (mut s, _) = open_lan(vec![resource("fs-mine", ResourceType::Filesystem, None)]).await;
    let peer = s.peer_id.clone();
    let stranger = "f".repeat(32);
    let offered = [
        (format!("fs-{peer}"), ResourceType::Filesystem),
        (format!("terminal-{peer}"), ResourceType::Terminal),
        (format!("desktop-{peer}"), ResourceType::RemoteDesktop),
        (format!("fs-{stranger}"), ResourceType::Filesystem),
        ("b-scratch".to_string(), ResourceType::Filesystem),
        (format!("sync-{peer}"), ResourceType::SyncFolder),
        ("fs-mine".to_string(), ResourceType::Filesystem),
    ];
    s.deliver(
        None,
        P2pMessage::HandshakeResponse {
            resources: offered
                .iter()
                .map(|(id, kind)| resource(id, kind.clone(), Some(generate_session_token())))
                .collect(),
        },
    )
    .await;
    s.verified_handshake().await;

    let announced = s.lan_session_up();
    assert_eq!(announced.len(), 1);
    let kept: Vec<&str> = announced[0].iter().map(|r| r.id.as_str()).collect();
    assert_eq!(kept, [format!("fs-{peer}"), format!("terminal-{peer}")]);
    assert!(s.key(&format!("fs-{peer}")).await.is_some());
    for dropped in [
        format!("desktop-{peer}"),
        "b-scratch".to_string(),
        format!("fs-{stranger}"),
        format!("sync-{peer}"),
    ] {
        assert_eq!(s.key(&dropped).await, None, "{dropped}");
    }
}

#[test]
fn a_lan_session_signals_through_its_tunnel() {
    let candidate = || RtcSignal::IceCandidate {
        candidate: "candidate:1 1 udp 1 192.168.1.2 5000 typ host".to_string(),
        sdp_mid: None,
        sdp_mline_index: None,
    };
    assert!(matches!(
        signal_cmd(Link::Lan { key: [7; 32] }, "peer".to_string(), candidate()),
        NetCmd::SendLanSignal(to, RtcSignal::IceCandidate { .. }) if to == "peer"
    ));
    assert!(matches!(
        signal_cmd(Link::Account, "peer".to_string(), candidate()),
        NetCmd::Send(WsMessage::RtcSignal(envelope)) if envelope.to_node_id == "peer"
    ));
}

#[cfg(feature = "feature-rdesk")]
mod remote_input {
    use super::*;
    use crate::desktop::{DesktopProvider, FrameCallback, StatusCallback};

    static APPLIED: AtomicUsize = AtomicUsize::new(0);

    struct CountingDesktop;

    impl DesktopProvider for CountingDesktop {
        fn start_capture(
            &self,
            _stop_flag: Arc<std::sync::atomic::AtomicBool>,
            _force_select: bool,
            _on_frame: FrameCallback,
            _on_status: StatusCallback,
        ) {
        }

        fn primary_screen_size(&self) -> Option<(usize, usize)> {
            None
        }

        fn apply_input(&self, _event: &nodeinnet_p2p::DesktopInputEvent) {
            APPLIED.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn input(resource_id: &str) -> P2pMessage {
        P2pMessage::RemoteDesktopInput {
            resource_id: resource_id.to_string(),
            event: nodeinnet_p2p::DesktopInputEvent::MouseMove { x: 1, y: 1 },
        }
    }

    #[tokio::test]
    async fn remote_desktop_input_needs_my_active_desktop() {
        let _ = crate::desktop::install_desktop_provider(Arc::new(CountingDesktop));
        let mut idle = resource("desktop-idle", ResourceType::RemoteDesktop, None);
        idle.is_active = false;
        let mut s = open(vec![
            resource("desktop-mine", ResourceType::RemoteDesktop, None),
            idle,
            resource("fs-mine", ResourceType::Filesystem, None),
        ])
        .await;
        let theirs = generate_session_token();
        s.deliver(
            None,
            P2pMessage::HandshakeResponse {
                resources: vec![resource(
                    "desktop-theirs",
                    ResourceType::RemoteDesktop,
                    Some(theirs.clone()),
                )],
            },
        )
        .await;
        s.verified_handshake().await;
        let sent = s.sent_handshake_responses();
        assert!(s.key("desktop-idle").await.is_none());
        let idle_key = generate_session_token();
        s.ctx
            .node_context
            .session_keys
            .lock()
            .await
            .insert("desktop-idle".to_string(), idle_key.clone());

        for (id, key) in [
            ("desktop-theirs", theirs),
            ("desktop-idle", idle_key),
            ("fs-mine", token_of(&sent, "fs-mine")),
        ] {
            let message = input(id);
            s.deliver(signed(&key, &message), message).await;
        }
        assert_eq!(APPLIED.load(Ordering::SeqCst), 0);

        let message = input("desktop-mine");
        s.deliver(signed(&token_of(&sent, "desktop-mine"), &message), message)
            .await;
        assert_eq!(APPLIED.load(Ordering::SeqCst), 1);
    }
}
