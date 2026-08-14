//! Real-transport integration tests: two live `WebRtcClient`s connect to each
//! other in-process over the actual `webrtc-rs` stack (real ICE/DTLS/SCTP/
//! DataChannel), complete the Zero-Trust handshake, and exchange messages.
//!
//! Unlike `src/tests` (which mocks `NodeContext`) these tests exercise the true
//! transport, so they validate behaviour that a mock cannot — in particular that
//! the chunk framing/reassembly in [`super::chunking`] survives real SCTP
//! fragmentation, and that an **ICE restart** renegotiated on the existing
//! `PeerConnection` preserves the authenticated session and DataChannel.
//!
//! Signalling that the production build routes through the WebSocket server is
//! shuttled here directly between the two clients: SDP via the return values of
//! `create_offer` / `accept_offer_and_answer` / `apply_answer`, and trickle ICE
//! candidates via each client's `NetCmd` channel (buffered until the peer's
//! remote description is set, then added directly).
//!
//! These tests need loopback UDP; they are `#[ignore]`d by default so the normal
//! `cargo test` run stays hermetic. Each test drives two real PeerConnections, so
//! run them serially (parallel runs saturate loopback ICE and flake):
//! `cargo test -p client-core -- --ignored --test-threads=1 loopback`.

use super::WebRtcClient;
use crate::{AppEventHandler, NetCmd};
use nodeinnet_p2p::rtc::RtcSignal;
use nodeinnet_p2p::{NodeInfo, P2pMessage, WsMessage};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

/// Minimal `AppEventHandler` that records inbound P2P messages for assertions.
struct TestHandler {
    label: &'static str,
    received: Arc<Mutex<Vec<P2pMessage>>>,
    verbose: bool,
}

impl TestHandler {
    fn new(label: &'static str, verbose: bool) -> (Arc<Self>, Arc<Mutex<Vec<P2pMessage>>>) {
        let received = Arc::new(Mutex::new(Vec::new()));
        (
            Arc::new(Self {
                label,
                received: received.clone(),
                verbose,
            }),
            received,
        )
    }
}

#[async_trait::async_trait]
impl AppEventHandler for TestHandler {
    async fn on_log(&self, msg: String) {
        if self.verbose {
            println!("[{}] {}", self.label, msg);
        }
    }
    async fn on_connected(&self) {}
    async fn on_disconnected(&self) {}
    async fn on_update_nodes(&self, _nodes: Vec<NodeInfo>) {}
    async fn on_download_complete(&self, _path: std::path::PathBuf) {}
    async fn on_p2p_message(&self, msg: P2pMessage) {
        self.received.lock().await.push(msg);
    }
    async fn on_p2p_connected(&self, _peer_id: String) {}
    async fn on_p2p_disconnected(&self, _peer_id: String) {}
}

fn make_node(id: &str, public_key: &str) -> NodeInfo {
    NodeInfo {
        id: id.to_string(),
        name: id.to_string(),
        os: "test".to_string(),
        version: "0.0.0".to_string(),
        app_type: "test".to_string(),
        build_type: "debug".to_string(),
        public_key: public_key.to_string(),
        resources: vec![],
        is_online: true,
        last_used: 0,
        is_temporary: false,
    }
}

type IceBuffer = Arc<Mutex<Vec<(String, Option<String>, Option<u16>)>>>;

/// Drain each `NetCmd` the source client emits; forward its trickle ICE
/// candidates to `target`. Candidates that arrive before `ready` is set (i.e.
/// before the target has a remote description) are buffered into `buf`. The
/// router keeps running for the lifetime of the test so ICE-restart candidates
/// are forwarded too.
fn spawn_ice_router(
    mut rx: mpsc::Receiver<NetCmd>,
    target: Arc<WebRtcClient>,
    ready: Arc<AtomicBool>,
    buf: IceBuffer,
) {
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            if let NetCmd::Send(WsMessage::RtcSignal(env)) = cmd {
                if let RtcSignal::IceCandidate {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                } = env.signal
                {
                    if ready.load(Ordering::SeqCst) {
                        let _ = target
                            .add_ice_candidate(candidate, sdp_mid, sdp_mline_index)
                            .await;
                    } else {
                        buf.lock().await.push((candidate, sdp_mid, sdp_mline_index));
                    }
                }
            }
        }
    });
}

/// Mark a peer ready to receive candidates and flush any that were buffered.
async fn flush_ready(ready: &Arc<AtomicBool>, buf: &IceBuffer, target: &Arc<WebRtcClient>) {
    ready.store(true, Ordering::SeqCst);
    let pending: Vec<_> = buf.lock().await.drain(..).collect();
    for (candidate, sdp_mid, sdp_mline_index) in pending {
        let _ = target
            .add_ice_candidate(candidate, sdp_mid, sdp_mline_index)
            .await;
    }
}

/// Poll until both clients have flipped `is_authenticated`, or time out.
async fn wait_for_auth(a: &Arc<WebRtcClient>, b: &Arc<WebRtcClient>, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if a.node_context.is_authenticated.load(Ordering::Relaxed)
            && b.node_context.is_authenticated.load(Ordering::Relaxed)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Poll a handler's inbox for a `TextMessage` whose text matches `expect`.
async fn wait_for_text(
    inbox: &Arc<Mutex<Vec<P2pMessage>>>,
    expect: &str,
    timeout: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        {
            let guard = inbox.lock().await;
            for m in guard.iter() {
                if let P2pMessage::TextMessage { text } = m {
                    if text == expect {
                        return true;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn build_client(
    my: &NodeInfo,
    target_id: &str,
    private_key: &str,
    verbose: bool,
    label: &'static str,
) -> (
    Arc<WebRtcClient>,
    mpsc::Receiver<NetCmd>,
    Arc<Mutex<Vec<P2pMessage>>>,
) {
    let (handler, inbox) = TestHandler::new(label, verbose);
    let (net_tx, net_rx) = mpsc::channel(256);
    let cfg = client_config::AppConfig::new(&format!("client-core-itest-{}", my.id));
    let client = WebRtcClient::new(
        handler,
        net_tx,
        my.clone(),
        target_id.to_string(),
        private_key.to_string(),
        None,
        cfg,
    )
    .await
    .expect("WebRtcClient::new failed");
    (Arc::new(client), net_rx, inbox)
}

/// Bring up two authenticated peers over real loopback WebRTC and return them
/// with their inboxes. Panics if the handshake does not complete.
async fn establish_authenticated_pair(
    verbose: bool,
) -> (
    Arc<WebRtcClient>,
    Arc<WebRtcClient>,
    Arc<Mutex<Vec<P2pMessage>>>,
) {
    let (a_priv, a_pub) = nodeinnet_p2p::crypto::generate_ed25519_keypair();
    let (b_priv, b_pub) = nodeinnet_p2p::crypto::generate_ed25519_keypair();
    let a_id = uuid::Uuid::new_v4().to_string();
    let b_id = uuid::Uuid::new_v4().to_string();
    let a_info = make_node(&a_id, &a_pub);
    let b_info = make_node(&b_id, &b_pub);

    // Both peers must trust each other's public key (production does this via the
    // signalling server's NodesList / PeersSync).
    nodeinnet_p2p::update_known_public_keys(&[a_info.clone(), b_info.clone()]);

    let (a, a_net_rx, _a_inbox) = build_client(&a_info, &b_id, &a_priv, verbose, "A").await;
    let (b, b_net_rx, b_inbox) = build_client(&b_info, &a_id, &b_priv, verbose, "B").await;

    // A's emitted candidates flow to B and vice-versa; buffer until the receiver
    // has set its remote description. Routers stay alive for the whole test.
    let a_ready = Arc::new(AtomicBool::new(false));
    let b_ready = Arc::new(AtomicBool::new(false));
    let a_buf: IceBuffer = Arc::new(Mutex::new(Vec::new()));
    let b_buf: IceBuffer = Arc::new(Mutex::new(Vec::new()));
    spawn_ice_router(a_net_rx, b.clone(), b_ready.clone(), b_buf.clone());
    spawn_ice_router(b_net_rx, a.clone(), a_ready.clone(), a_buf.clone());

    // SDP exchange (A is the caller/offerer, B the callee/answerer).
    let offer = a.create_offer().await.expect("create_offer");
    let answer = b.accept_offer_and_answer(offer).await.expect("answer");
    flush_ready(&b_ready, &b_buf, &b).await; // B has a remote description now
    a.apply_answer(answer).await.expect("apply_answer");
    flush_ready(&a_ready, &a_buf, &a).await; // A has a remote description now

    assert!(
        wait_for_auth(&a, &b, Duration::from_secs(30)).await,
        "peers did not complete Zero-Trust authentication within 30s"
    );
    (a, b, b_inbox)
}

/// Close both peers' PeerConnections so their ICE agents/tasks stop and free
/// loopback sockets — otherwise lingering connections from earlier tests saturate
/// ICE and flake later ones (these tests each drive two real PeerConnections).
async fn close_pair(a: &Arc<WebRtcClient>, b: &Arc<WebRtcClient>) {
    let _ = a.peer_connection.close().await;
    let _ = b.peer_connection.close().await;
}

/// End-to-end: two nodes complete the real Zero-Trust WebRTC handshake and a
/// 100 KB (multi-chunk) `TextMessage` round-trips intact — the real-transport
/// validation of the `chunking` framing/reassembly refactor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs loopback UDP; run with --ignored"]
async fn loopback_handshake_and_large_message() {
    let verbose = std::env::var("RTC_TEST_VERBOSE").is_ok();
    let (a, b, b_inbox) = establish_authenticated_pair(verbose).await;

    // 100 KB forces ~10 framed chunks over the real DataChannel/SCTP path.
    let big = "X".repeat(100_000);
    a.send_p2p_message(P2pMessage::TextMessage { text: big.clone() })
        .await
        .expect("send_p2p_message");

    assert!(
        wait_for_text(&b_inbox, &big, Duration::from_secs(15)).await,
        "large multi-chunk message did not arrive intact"
    );
    close_pair(&a, &b).await;
}

/// An ICE restart renegotiated on the existing `PeerConnection` must preserve the
/// authenticated session and DataChannel (the whole point of fix #2: recover from
/// a transient path change without a full teardown + re-handshake). We drive the
/// same in-place renegotiation the production `Disconnected` handler + orchestrator
/// perform, then verify auth survived and a fresh message still flows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs loopback UDP; run with --ignored"]
async fn loopback_ice_restart_preserves_session() {
    use webrtc::peer_connection::offer_answer_options::RTCOfferOptions;

    let verbose = std::env::var("RTC_TEST_VERBOSE").is_ok();
    let (a, b, b_inbox) = establish_authenticated_pair(verbose).await;

    // Sanity: a message flows before the restart.
    a.send_p2p_message(P2pMessage::TextMessage {
        text: "before-restart".to_string(),
    })
    .await
    .unwrap();
    assert!(
        wait_for_text(&b_inbox, "before-restart", Duration::from_secs(10)).await,
        "baseline message before ICE restart did not arrive"
    );

    // Perform an ICE restart from the offerer (A) against the EXISTING peer
    // connection — exactly what the Disconnected handler does, answered in place
    // by B the way the orchestrator does.
    let opts = RTCOfferOptions {
        ice_restart: true,
        voice_activity_detection: false,
    };
    let offer = a
        .peer_connection
        .create_offer(Some(opts))
        .await
        .expect("ice-restart create_offer");
    a.peer_connection
        .set_local_description(offer)
        .await
        .expect("set_local_description");
    let restart_sdp = a
        .peer_connection
        .local_description()
        .await
        .expect("local_description")
        .sdp;
    let restart_answer = b
        .accept_offer_and_answer(restart_sdp)
        .await
        .expect("ice-restart answer");
    a.apply_answer(restart_answer)
        .await
        .expect("apply ice-restart answer");

    // Give ICE a moment to reconverge on the fresh credentials.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The authenticated session must NOT have been torn down by the restart.
    assert!(
        a.node_context.is_authenticated.load(Ordering::Relaxed),
        "A lost authentication across ICE restart"
    );
    assert!(
        b.node_context.is_authenticated.load(Ordering::Relaxed),
        "B lost authentication across ICE restart"
    );

    // And the DataChannel must still carry traffic after the restart.
    a.send_p2p_message(P2pMessage::TextMessage {
        text: "after-restart".to_string(),
    })
    .await
    .unwrap();
    assert!(
        wait_for_text(&b_inbox, "after-restart", Duration::from_secs(20)).await,
        "message after ICE restart did not arrive — session was not preserved"
    );
    close_pair(&a, &b).await;
}

/// Two tasks writing large multi-chunk messages to the SAME DataChannel
/// concurrently, serialized by the shared per-connection `dc_write_lock`, must
/// both arrive intact. Without the lock their length-prefixed chunks interleave
/// and the receiver's sequential reassembler corrupts them (documented by
/// `chunking::interleaved_writers_corrupt_stream`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs loopback UDP; run with --ignored"]
async fn loopback_concurrent_writes_stay_intact() {
    let verbose = std::env::var("RTC_TEST_VERBOSE").is_ok();
    let (a, b, b_inbox) = establish_authenticated_pair(verbose).await;

    let dc = a
        .data_channel
        .lock()
        .await
        .clone()
        .expect("A should have an open DataChannel after auth");
    let lock = a.node_context.dc_write_lock.clone();
    let handler: Arc<dyn AppEventHandler> = TestHandler::new("W", verbose).0;

    // Two distinct large (multi-chunk) payloads, encoded exactly like the pipe.
    let text_a = "A".repeat(45_000);
    let text_b = "B".repeat(45_000);
    let encode = |text: &str| {
        nodeinnet_p2p::p2p::to_bson_vec(&nodeinnet_p2p::SecuredP2pEnvelope {
            mac: None,
            message: P2pMessage::TextMessage {
                text: text.to_string(),
            },
        })
        .expect("bson encode")
    };
    let bytes_a = encode(&text_a);
    let bytes_b = encode(&text_b);

    // Fire both writes concurrently against the same channel.
    let t1 = {
        let (dc, lock, handler, data) =
            (dc.clone(), lock.clone(), handler.clone(), bytes_a.clone());
        tokio::spawn(
            async move { super::send_chunked_binary(&dc, &data, 10240, &handler, &lock).await },
        )
    };
    let t2 = {
        let (dc, lock, handler, data) =
            (dc.clone(), lock.clone(), handler.clone(), bytes_b.clone());
        tokio::spawn(
            async move { super::send_chunked_binary(&dc, &data, 10240, &handler, &lock).await },
        )
    };
    let _ = t1.await.unwrap();
    let _ = t2.await.unwrap();

    // Both messages must arrive intact despite concurrent writers.
    assert!(
        wait_for_text(&b_inbox, &text_a, Duration::from_secs(15)).await,
        "first concurrent message was lost/corrupted"
    );
    assert!(
        wait_for_text(&b_inbox, &text_b, Duration::from_secs(15)).await,
        "second concurrent message was lost/corrupted"
    );
    close_pair(&a, &b).await;
}
