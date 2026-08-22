pub mod chunking;
pub mod core;
#[cfg(feature = "feature-rdesk")]
pub mod video_utils;

#[cfg(test)]
mod loopback_tests;

use crate::NetCmd;
use nodeinnet_p2p::P2pMessage;
use nodeinnet_p2p::rtc::{RtcSignal, RtcSignalEnvelope};
use nodeinnet_p2p::{NodeInfo, WsMessage};
use p2p_node::NodeContext;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "feature-rdesk")]
use crate::desktop::{CapturedFrame, DesktopStreamStatus, desktop_provider};
#[cfg(feature = "feature-rdesk")]
use base64::Engine;
#[cfg(feature = "feature-rdesk")]
use openh264::decoder::Decoder;
#[cfg(feature = "feature-rdesk")]
use openh264::formats::YUVSource;
#[cfg(feature = "feature-rdesk")]
use rtp::codecs::h264::H264Packet;
#[cfg(feature = "feature-rdesk")]
use rtp::packetizer::Depacketizer;
#[cfg(feature = "feature-rdesk")]
use std::sync::OnceLock;
#[cfg(feature = "feature-rdesk")]
use std::sync::atomic::AtomicBool;
#[cfg(feature = "feature-rdesk")]
use webrtc::media::Sample;
#[cfg(feature = "feature-rdesk")]
use webrtc::track::track_local::TrackLocal;
#[cfg(feature = "feature-rdesk")]
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

#[cfg(feature = "feature-rdesk")]
type StreamKey = (uuid::Uuid, String);
#[cfg(feature = "feature-rdesk")]
type HostStream = (
    Arc<AtomicBool>,
    tokio::task::JoinHandle<()>,
    Arc<webrtc::rtp_transceiver::rtp_sender::RTCRtpSender>,
);
#[cfg(feature = "feature-rdesk")]
type HostStreamMap = Mutex<std::collections::HashMap<StreamKey, HostStream>>;
#[cfg(feature = "feature-rdesk")]
type OriginalSizeMap = Mutex<std::collections::HashMap<StreamKey, Arc<AtomicBool>>>;
#[cfg(feature = "feature-rdesk")]
type BitrateMap = Mutex<std::collections::HashMap<StreamKey, Arc<std::sync::atomic::AtomicU32>>>;

#[cfg(feature = "feature-rdesk")]
static ACTIVE_HOST_STREAMS: OnceLock<HostStreamMap> = OnceLock::new();
#[cfg(feature = "feature-rdesk")]
static ACTIVE_HOST_ORIGINAL_SIZE: OnceLock<OriginalSizeMap> = OnceLock::new();

#[cfg(feature = "feature-rdesk")]
fn active_streams() -> &'static HostStreamMap {
    ACTIVE_HOST_STREAMS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(feature = "feature-rdesk")]
fn active_original_sizes() -> &'static OriginalSizeMap {
    ACTIVE_HOST_ORIGINAL_SIZE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

#[cfg(feature = "feature-rdesk")]
fn active_bitrates() -> &'static BitrateMap {
    static ACTIVE_HOST_BITRATES: std::sync::OnceLock<BitrateMap> = std::sync::OnceLock::new();
    ACTIVE_HOST_BITRATES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

const P2P_PING_INTERVAL_SECS: u64 = 15;
const P2P_PONG_TIMEOUT_MS: u64 = 45_000;

#[cfg(feature = "feature-rdesk")]
struct SimpleYuvSource<'a> {
    pub width: i32,
    pub height: i32,
    pub y: &'a [u8],
    pub u: &'a [u8],
    pub v: &'a [u8],
}

#[cfg(feature = "feature-rdesk")]
impl<'a> YUVSource for SimpleYuvSource<'a> {
    fn width(&self) -> i32 {
        self.width
    }
    fn height(&self) -> i32 {
        self.height
    }
    fn y(&self) -> &[u8] {
        self.y
    }
    fn u(&self) -> &[u8] {
        self.u
    }
    fn v(&self) -> &[u8] {
        self.v
    }

    fn y_stride(&self) -> i32 {
        self.width
    }
    fn u_stride(&self) -> i32 {
        self.width / 2
    }
    fn v_stride(&self) -> i32 {
        self.width / 2
    }
}

async fn send_chunked_binary(
    dc: &Arc<webrtc::data_channel::RTCDataChannel>,
    data: &[u8],
    max_chunk_payload: usize,
    handler: &Arc<dyn crate::AppEventHandler>,
    write_lock: &Arc<Mutex<()>>,
) -> Result<(), String> {
    // Concurrent writers would interleave chunks and corrupt reassembly.
    let _write_guard = write_lock.lock().await;

    let send_start = std::time::Instant::now();
    let full_len = data.len();

    let frames = chunking::frame_chunks(data, max_chunk_payload);
    let chunks_count = frames.len();

    // Backpressure instead of a fixed per-chunk delay, so small messages never wait.
    const HIGH_WATER: usize = 1024 * 1024;
    const LOW_WATER: usize = 256 * 1024;
    for frame in frames {
        dc.send(&bytes::Bytes::from(frame))
            .await
            .map_err(|e| e.to_string())?;
        if dc.buffered_amount().await > HIGH_WATER {
            while dc.buffered_amount().await > LOW_WATER {
                tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
            }
        }
    }

    if full_len > max_chunk_payload {
        let final_buf = dc.buffered_amount().await;
        handler
            .on_log(format!(
                "📦 [CHUNKED-TIMING] {} bytes → {} chunks, total_time={}ms, final_buffered_amount={}",
                full_len,
                chunks_count,
                send_start.elapsed().as_millis(),
                final_buf
            ))
            .await;
    }
    Ok(())
}
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc as tokio_mpsc;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::sdp_type::RTCSdpType;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

async fn wait_until_signaling_stable(
    pc: &Arc<RTCPeerConnection>,
    timeout: std::time::Duration,
) -> bool {
    use webrtc::peer_connection::signaling_state::RTCSignalingState;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if pc.signaling_state() == RTCSignalingState::Stable {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(feature = "feature-rdesk")]
fn spawn_rdesk_renegotiation(
    pc: Arc<RTCPeerConnection>,
    node_context: NodeContext,
    handler: Arc<dyn crate::AppEventHandler>,
    resource_id: String,
) {
    tokio::spawn(async move {
        let _guard = node_context.negotiation_lock.lock().await;
        if !wait_until_signaling_stable(&pc, std::time::Duration::from_secs(5)).await {
            let _ = handler
                .on_log(format!(
                    "⚠️ [Reneg] Signaling still not stable before offer for {} — proceeding",
                    resource_id
                ))
                .await;
        }
        match pc.create_offer(None).await {
            Ok(offer) => {
                if let Err(e) = pc.set_local_description(offer).await {
                    let _ = handler
                        .on_log(format!("❌ Failed to set local offer: {:?}", e))
                        .await;
                    return;
                }
                if let Some(local_desc) = pc.local_description().await {
                    let sdp_b64 = base64::engine::general_purpose::STANDARD.encode(local_desc.sdp);
                    let _ = node_context
                        .outgoing_tx
                        .send(nodeinnet_p2p::OutboundP2pPayload::UnsignedMessage(
                            P2pMessage::RemoteDesktopSdpOffer {
                                resource_id: resource_id.clone(),
                                sdp: sdp_b64,
                            },
                        ))
                        .await;
                    let _ = handler
                        .on_log(format!(
                            "📤 Sent dynamic SDP Offer renegotiation for resource {}",
                            resource_id
                        ))
                        .await;
                }
                let _ = wait_until_signaling_stable(&pc, std::time::Duration::from_secs(5)).await;
            }
            Err(e) => {
                let _ = handler
                    .on_log(format!("❌ Failed to create dynamic SDP Offer: {:?}", e))
                    .await;
            }
        }
    });
}

#[derive(Clone)]
struct IncomingP2pContext {
    handler: std::sync::Arc<dyn crate::AppEventHandler>,
    dc: Arc<RTCDataChannel>,
    node_context: NodeContext,
    target_node_id: String,
    last_pong: Arc<AtomicU64>,
    net_tx: tokio_mpsc::Sender<crate::NetCmd>,
    peer_connection: Arc<RTCPeerConnection>,
    connection_id: uuid::Uuid,
}

async fn handle_incoming_p2p_message(msg_data: &[u8], ctx: IncomingP2pContext) {
    let IncomingP2pContext {
        handler,
        dc,
        node_context,
        target_node_id,
        last_pong,
        net_tx,
        peer_connection,
        connection_id,
    } = ctx;

    #[cfg(not(feature = "feature-rdesk"))]
    let _ = connection_id;

    handler
        .on_log(format!(
            "📥 [INCOMING BSON] from {}: size {} bytes",
            target_node_id,
            msg_data.len()
        ))
        .await;

    if let Ok(envelope) =
        nodeinnet_p2p::p2p::from_bson_slice::<nodeinnet_p2p::SecuredP2pEnvelope>(msg_data)
    {
        let p2p_msg = envelope.message;

        if !matches!(p2p_msg, P2pMessage::Pong(_)) && !matches!(p2p_msg, P2pMessage::Ping(_)) {
            let hex_str = msg_data
                .iter()
                .take(200)
                .map(|b| format!("{:02X}", b))
                .collect::<String>();
            let _hex_out = if msg_data.len() > 200 {
                format!("{}...[truncated, {} bytes total]", hex_str, msg_data.len())
            } else {
                hex_str
            };

            if let Ok(json) = serde_json::to_string(&p2p_msg) {
                let s = if json.len() > 1000 {
                    format!(
                        "{}... [truncated]",
                        json.chars().take(1000).collect::<String>()
                    )
                } else {
                    json.clone()
                };
                handler
                    .on_log(format!("📄 [INBOUND-DECODED] BSON->JSON: {}", s))
                    .await;
            }
        }

        if let P2pMessage::HandshakeResponse { ref resources } = p2p_msg {
            let mut log_str = "🔑 [AUTH] Received HandshakeResponse. Key saved:\n".to_string();
            let mut keys = node_context.session_keys.lock().await;
            let mut types = node_context.remote_resources.lock().await;
            for res in resources {
                log_str.push_str(&format!("  -> {:?} ({})\n", res.resource_type, res.id));
                types.insert(res.resource_type.clone(), res.id.clone());
                if let Some(token) = &res.session_token {
                    keys.insert(res.id.clone(), token.clone());
                }
            }
            drop(keys); // Release keys lock before log/send operations
            drop(types);
            handler.on_log(log_str).await;

            let was_authenticated = node_context.is_authenticated.swap(true, Ordering::SeqCst);
            handler
                .on_peer_state_changed(target_node_id.clone(), crate::P2pPeerState::Connected)
                .await;

            let _ = net_tx
                .send(crate::NetCmd::PeerConnected(
                    target_node_id.clone(),
                    resources.clone(),
                ))
                .await;

            if !was_authenticated {
                spawn_connection_type_poller(
                    peer_connection.clone(),
                    target_node_id.clone(),
                    handler.clone(),
                );
                let mut my_resources = node_context.my_info.resources.clone();
                {
                    let mut session_keys = node_context.session_keys.lock().await;
                    for res in my_resources.iter_mut() {
                        let token = nodeinnet_p2p::crypto::generate_session_token();
                        handler.on_log(format!(
                            "🔑 [P2P-NODE KEYGEN] Created local session token for resource: {} ({})",
                            res.id,
                            &token[..4]
                        )).await;
                        res.session_token = Some(token.clone());
                        session_keys.insert(res.id.clone(), token);
                    }
                }

                handler
                    .on_log(format!(
                        "🤝 Sending symmetric HandshakeResponse back to {}",
                        target_node_id
                    ))
                    .await;
                let return_msg = P2pMessage::HandshakeResponse {
                    resources: my_resources,
                };
                let envelope = nodeinnet_p2p::SecuredP2pEnvelope {
                    mac: None,
                    message: return_msg,
                };
                if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&envelope) {
                    let max_c = 10240;
                    let _ = send_chunked_binary(
                        &dc,
                        &bson_bytes,
                        max_c,
                        &handler,
                        &node_context.dc_write_lock,
                    )
                    .await;
                }
            }

            return;
        } else if let P2pMessage::PeersSync {
            ref nodes,
            ref addresses,
        } = p2p_msg
        {
            handler
                .on_log(format!(
                    "🔄 [MESH] Received PeersSync from {}: {} nodes, {} addresses",
                    target_node_id,
                    nodes.len(),
                    addresses.len()
                ))
                .await;

            nodeinnet_p2p::update_known_public_keys(nodes);
            node_context.config.update(
                "peers",
                |map: &mut std::collections::HashMap<String, nodeinnet_p2p::PeerConfig>| {
                    for node in nodes {
                        let entry = map.entry(node.id.clone()).or_default();
                        entry.public_key = node.public_key.clone();
                        entry.name = node.name.clone();
                        entry.os = node.os.clone();
                    }
                    for (peer_id, addrs) in addresses {
                        let entry = map.entry(peer_id.clone()).or_default();
                        entry.last_known_addresses = addrs.clone();
                    }
                },
            );
            node_context.config.save();

            let _ = net_tx
                .send(crate::NetCmd::MergeNodesList(nodes.clone()))
                .await;

            return;
        } else if let P2pMessage::Pong(timestamp_ms) = p2p_msg {
            last_pong.store(timestamp_ms, std::sync::atomic::Ordering::SeqCst);
            return;
        }

        if let Some(res_id) = p2p_msg.resource_id() {
            let keys = node_context.session_keys.lock().await;
            if let Some(token) = keys.get(res_id) {
                if let Some(received_mac) = envelope.mac {
                    if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&p2p_msg) {
                        if !nodeinnet_p2p::crypto::verify_hmac_sha256(
                            &bson_bytes,
                            token,
                            &received_mac,
                        ) {
                            handler.on_log(format!("🚨 SECURITY BREACH: Invalid HMAC signature for resource {}! Command blocked.", res_id)).await;
                            handler
                                .on_peer_state_changed(
                                    target_node_id.clone(),
                                    crate::P2pPeerState::Failed,
                                )
                                .await;
                            return;
                        }
                    } else {
                        return;
                    }
                } else {
                    handler.on_log(format!("🚨 SECURITY BREACH: Missing HMAC signature for resource {}! Command blocked.", res_id)).await;
                    handler
                        .on_peer_state_changed(target_node_id.clone(), crate::P2pPeerState::Failed)
                        .await;
                    return;
                }
            } else {
                handler.on_log(format!("🚨 SECURITY BREACH: No session key configured for resource {}! Command blocked.", res_id)).await;
                handler
                    .on_peer_state_changed(target_node_id.clone(), crate::P2pPeerState::Failed)
                    .await;
                return;
            }
        }

        if !node_context.is_authenticated.load(Ordering::Relaxed)
            && !matches!(p2p_msg, P2pMessage::Handshake { .. })
        {
            let mut auth_successful = false;
            for _ in 0..25 {
                if node_context.is_authenticated.load(Ordering::Relaxed) {
                    auth_successful = true;
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }

            if !auth_successful {
                handler
                    .on_log(format!(
                        "🛡️ [Zero-Trust Firewall]: Blocked unauthenticated message from {}",
                        target_node_id
                    ))
                    .await;
                handler
                    .on_peer_state_changed(target_node_id.clone(), crate::P2pPeerState::Failed)
                    .await;
                return;
            }
        }

        #[cfg(feature = "feature-rdesk")]
        if let P2pMessage::RemoteDesktopRequest {
            ref resource_id,
            start,
            original_size,
            bitrate_bps,
            force_select,
        } = p2p_msg
        {
            println!(
                "[RTC LOG] Received RemoteDesktopRequest for resource_id: {}, start: {}, original_size: {}, force_select: {}, bitrate_bps: {:?}",
                resource_id, start, original_size, force_select, bitrate_bps
            );
            let success = node_context.my_info.resources.iter().any(|r| {
                r.id == *resource_id
                    && r.is_active
                    && r.resource_type == nodeinnet_p2p::ResourceType::RemoteDesktop
            });
            if success {
                let target_bitrate = bitrate_bps.unwrap_or(800_000);
                handler.on_log(format!("🟢 RemoteDesktopRequest approved for resource {} (start={}, original_size={}, force_select={}, bitrate_bps={:?})", resource_id, start, original_size, force_select, bitrate_bps)).await;

                let mut screen_w = None;
                let mut screen_h = None;
                if start {
                    if let Some((w, h)) = desktop_provider().and_then(|p| p.primary_screen_size()) {
                        println!("[RTC LOG] Detected primary screen size: {}x{}", w, h);
                        screen_w = Some(w);
                        screen_h = Some(h);
                    } else {
                        println!("[RTC LOG] Failed to detect primary screen size");
                    }
                }

                let _ = node_context
                    .outgoing_tx
                    .send(nodeinnet_p2p::OutboundP2pPayload::UnsignedMessage(
                        P2pMessage::RemoteDesktopResponse {
                            resource_id: resource_id.clone(),
                            success: true,
                            error_msg: None,
                            width: screen_w,
                            height: screen_h,
                        },
                    ))
                    .await;

                if start {
                    let resource_id_cloned = resource_id.clone();
                    let handler_cloned = handler.clone();
                    let peer_conn_cloned = peer_connection.clone();
                    let _dc_cloned = dc.clone();

                    let mut streams = active_streams().lock().await;
                    let key = (connection_id, resource_id_cloned.clone());
                    if streams.contains_key(&key) {
                        handler_cloned.on_log(format!("⚠️ Desktop stream already active for resource {}. Updating parameters: original_size={}, bitrate={}.", resource_id_cloned, original_size, target_bitrate)).await;
                        if let Some(flag) = active_original_sizes().lock().await.get(&key) {
                            flag.store(original_size, Ordering::Relaxed);
                        }
                        if let Some(flag) = active_bitrates().lock().await.get(&key) {
                            flag.store(target_bitrate, Ordering::Relaxed);
                        }
                    } else {
                        handler_cloned.on_log(format!("🚀 Starting dynamic screen capturer and H.264 dynamic track for resource {} under key: {:?}", resource_id_cloned, key)).await;

                        let video_track = Arc::new(TrackLocalStaticSample::new(
                            webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability {
                                mime_type: "video/h264".to_string(),
                                ..Default::default()
                            },
                            format!("video-{}", resource_id_cloned),
                            format!("stream-{}", resource_id_cloned),
                        ));

                        match peer_conn_cloned.add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>).await {
                            Ok(rtp_sender) => {
                                 let stop_flag = Arc::new(AtomicBool::new(false));
                                 let stop_flag_capture = stop_flag.clone();
                                 let handler_capture = handler_cloned.clone();
                                 let original_size_flag = Arc::new(AtomicBool::new(original_size));
                                 let original_size_capture = original_size_flag.clone();
                                 let bitrate_flag = Arc::new(std::sync::atomic::AtomicU32::new(target_bitrate));
                                 let bitrate_capture = bitrate_flag.clone();

                                 let force_keyframe = Arc::new(AtomicBool::new(false));
                                 let force_keyframe_encoder = force_keyframe.clone();
                                 let rtcp_sender = rtp_sender.clone();
                                 let rtcp_stop = stop_flag.clone();
                                 let rtcp_handler = handler_cloned.clone();
                                 let rtcp_res_id = resource_id_cloned.clone();
                                 tokio::spawn(async move {
                                     use webrtc::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
                                     use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
                                     loop {
                                         if rtcp_stop.load(Ordering::Relaxed) {
                                             break;
                                         }
                                         match tokio::time::timeout(std::time::Duration::from_secs(1), rtcp_sender.read_rtcp()).await {
                                             Ok(Ok((packets, _))) => {
                                                 let want_key = packets.iter().any(|p| {
                                                     p.as_any().downcast_ref::<PictureLossIndication>().is_some()
                                                         || p.as_any().downcast_ref::<FullIntraRequest>().is_some()
                                                 });
                                                 if want_key {
                                                     force_keyframe.store(true, Ordering::Relaxed);
                                                     let _ = rtcp_handler.on_log(format!(
                                                         "🔑 [RTCP] PLI/FIR from viewer for resource {} — forcing keyframe",
                                                         rtcp_res_id
                                                     )).await;
                                                 }
                                             }
                                             Ok(Err(_)) => break, // sender closed / track removed
                                             Err(_) => continue,  // timeout → re-check stop flag
                                         }
                                     }
                                 });

                                 let join_handle = tokio::spawn(async move {
                                     let mut encoder: Option<openh264::encoder::Encoder> = None;
                                     let mut current_width = 0;
                                     let mut current_height = 0;
                                     let mut current_bitrate = 0;

                                     let raw_frame_buffer = Arc::new(std::sync::Mutex::new(None));
                                     let raw_frame_buffer_capture = raw_frame_buffer.clone();

                                     let stop_flag_inner = stop_flag_capture.clone();
                                     let handler_inner = handler_capture.clone();
                                     let rt_handle = tokio::runtime::Handle::current();
                                     if let Some(provider) = desktop_provider() {
                                         provider.start_capture(
                                             stop_flag_inner,
                                             force_select,
                                             Box::new(move |frame: CapturedFrame| {
                                                 let mut guard = raw_frame_buffer_capture.lock().unwrap();
                                                 *guard = Some(frame);
                                             }),
                                             Box::new(move |status: DesktopStreamStatus| {
                                                 let h = handler_inner.clone();
                                                 rt_handle.spawn(async move {
                                                     let _ = h.on_log(format!("📺 [Desktop Capturer Status] {:?}", status)).await;
                                                 });
                                             }),
                                         );
                                     }

                                     let mut _frame_count = 0;
                                     let mut consecutive_none_frames = 0;
                                     while !stop_flag_capture.load(Ordering::Relaxed) {
                                         let start_time = std::time::Instant::now();

                                         let frame_opt = {
                                             let mut guard = raw_frame_buffer.lock().unwrap();
                                             guard.take()
                                         };

                                         let frame = if let Some(f) = frame_opt {
                                             consecutive_none_frames = 0;
                                             f
                                         } else {
                                             consecutive_none_frames += 1;
                                             if consecutive_none_frames % 200 == 0 {
                                                 let _ = handler_capture.on_log(format!(
                                                     "⚠️ [Encoder-Diag] No captured frames from platform capturer for {} ticks (~2s). Capture is stalled!",
                                                     consecutive_none_frames
                                                 )).await;
                                             }
                                             tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                                             continue;
                                         };

                                          let mut target_w = frame.width;
                                          let mut target_h = frame.height;
                                          if !original_size_capture.load(Ordering::Relaxed) {
                                              let max_dim = 1280;
                                              if target_w > max_dim || target_h > max_dim {
                                                  if target_w > target_h {
                                                      let scale = max_dim as f64 / target_w as f64;
                                                      target_w = max_dim;
                                                      target_h = (target_h as f64 * scale) as usize;
                                                  } else {
                                                      let scale = max_dim as f64 / target_h as f64;
                                                      target_h = max_dim;
                                                      target_w = (target_w as f64 * scale) as usize;
                                                  }
                                              }
                                          }
                                         if target_w % 2 != 0 {
                                             target_w -= 1;
                                         }
                                         if target_h % 2 != 0 {
                                             target_h -= 1;
                                         }

                                         let target_bitrate = bitrate_capture.load(Ordering::Relaxed);
                                         if encoder.is_none() || current_width != target_w || current_height != target_h {
                                             let _ = handler_capture.on_log(format!(
                                                 "📺 Initializing/Recreating OpenH264 encoder: native {}x{}, target {}x{}, bitrate {} bps",
                                                 frame.width, frame.height, target_w, target_h, target_bitrate
                                             )).await;

                                             let config = openh264::encoder::EncoderConfig::new(target_w as u32, target_h as u32)
                                                 .set_bitrate_bps(target_bitrate)
                                                 .max_frame_rate(30.0);

                                             match openh264::encoder::Encoder::with_config(config) {
                                                 Ok(e) => {
                                                     encoder = Some(e);
                                                     current_width = target_w;
                                                     current_height = target_h;
                                                     current_bitrate = target_bitrate;
                                                 }
                                                 Err(e) => {
                                                     let _ = handler_capture.on_log(format!("❌ Failed to build openh264 encoder: {:?}", e)).await;
                                                     tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                                     continue;
                                                 }
                                             }
                                         } else if current_bitrate != target_bitrate {
                                             if let Some(ref mut enc) = encoder {
                                                 let mut info = openh264_sys2::SBitrateInfo {
                                                     iLayer: openh264_sys2::SPATIAL_LAYER_ALL,
                                                     iBitrate: target_bitrate as std::os::raw::c_int,
                                                 };
                                                 let rc = unsafe {
                                                     enc.raw_api().set_option(
                                                         openh264_sys2::ENCODER_OPTION_BITRATE,
                                                         &mut info as *mut _ as *mut std::os::raw::c_void,
                                                     )
                                                 };
                                                 if rc == 0 {
                                                     current_bitrate = target_bitrate;
                                                     let _ = handler_capture.on_log(format!(
                                                         "📺 Adjusted encoder bitrate live to {} bps (no recreate)",
                                                         target_bitrate
                                                     )).await;
                                                 } else {
                                                     let _ = handler_capture.on_log(format!(
                                                         "⚠️ SetOption(BITRATE) failed (rc={}); keeping current bitrate {}",
                                                         rc, current_bitrate
                                                     )).await;
                                                 }
                                             }
                                         }

                                         let y_size = current_width * current_height;
                                         let uv_size = (current_width / 2) * (current_height / 2);

                                         let yuv_data = video_utils::bgra_to_yuv420p(&frame.data, frame.width, frame.height, current_width, current_height);

                                         _frame_count += 1;

                                         let y_plane = &yuv_data[0..y_size];
                                         let u_plane = &yuv_data[y_size..(y_size + uv_size)];
                                         let v_plane = &yuv_data[(y_size + uv_size)..];

                                         let yuv_source = SimpleYuvSource {
                                             width: current_width as i32,
                                             height: current_height as i32,
                                             y: y_plane,
                                             u: u_plane,
                                             v: v_plane,
                                         };

                                         if force_keyframe_encoder.swap(false, Ordering::Relaxed)
                                             && let Some(ref mut enc) = encoder {
                                                 unsafe { enc.raw_api().force_intra_frame(true); }
                                             }

                                         let bits = if let Some(ref mut enc) = encoder {
                                             if let Ok(encoded) = enc.encode(&yuv_source) {
                                                 encoded.to_vec()
                                             } else {
                                                 Vec::new()
                                             }
                                         } else {
                                             Vec::new()
                                         };

                                         if !bits.is_empty() {
                                             let sample = Sample {
                                                 data: bits.into(),
                                                 duration: std::time::Duration::from_millis(66),
                                                 ..Default::default()
                                             };

                                             let encoded_bytes = sample.data.len();
                                             if encoded_bytes > 30720 {
                                                 let _ = handler_capture.on_log(format!(
                                                     "⚠️ [ENCODER-SPIKE] Large I-frame! {} bytes at frame {}",
                                                     encoded_bytes, _frame_count
                                                 )).await;
                                             }

                                             if _frame_count % 30 == 0 {
                                                 let _ = handler_capture.on_log(format!(
                                                     "📺 [Encoder-Diag] Dynamic Video Loop: frame_count={}, target_dimensions={}x{}, encoded_slice_bytes={}",
                                                     _frame_count, current_width, current_height, encoded_bytes
                                                 )).await;
                                             }

                                             if let Err(e) = video_track.write_sample(&sample).await {
                                                 let _ = handler_capture.on_log(format!("❌ Failed to write track sample: {:?}", e)).await;
                                                 break;
                                             }
                                         } else {
                                             if _frame_count % 30 == 0 {
                                                 let _ = handler_capture.on_log(format!(
                                                     "⚠️ [Encoder-Diag] Frame #{} was captured and processed, but H.264 slice was empty/skipped by encoder!",
                                                     _frame_count
                                                 )).await;
                                             }
                                         }

                                         let elapsed = start_time.elapsed();
                                         let target_delay = std::time::Duration::from_millis(66);
                                         if elapsed < target_delay {
                                             tokio::time::sleep(target_delay - elapsed).await;
                                         }
                                     }
                                 });

                                 streams.insert(key.clone(), (stop_flag, join_handle, rtp_sender));
                                 active_original_sizes().lock().await.insert(key.clone(), original_size_flag);
                                 active_bitrates().lock().await.insert(key.clone(), bitrate_flag);

                                spawn_rdesk_renegotiation(
                                    peer_conn_cloned.clone(),
                                    node_context.clone(),
                                    handler_cloned.clone(),
                                    resource_id_cloned.clone(),
                                );
                            }
                            Err(e) => {
                                handler_cloned.on_log(format!("❌ Failed to add video track for resource {}: {:?}", resource_id_cloned, e)).await;
                            }
                        }
                    }
                } else {
                    let mut streams = active_streams().lock().await;
                    let key = (connection_id, resource_id.clone());
                    handler
                        .on_log(format!(
                            "🛑 [Stop Request] Searching stream for key: {:?}",
                            key
                        ))
                        .await;
                    if let Some((stop_flag, join_handle, rtp_sender)) = streams.remove(&key) {
                        stop_flag.store(true, Ordering::SeqCst);
                        join_handle.abort();
                        active_original_sizes().lock().await.remove(&key);
                        active_bitrates().lock().await.remove(&key);
                        let _ = peer_connection.remove_track(&rtp_sender).await;
                        handler
                            .on_log(format!(
                                "🛑 Stopped screen streaming for resource {}",
                                resource_id
                            ))
                            .await;
                    } else {
                        let current_keys: Vec<_> = streams.keys().cloned().collect();
                        handler.on_log(format!("⚠️ [Stop Request Error] No active stream found for key: {:?}. Active keys: {:?}", key, current_keys)).await;
                    }

                    spawn_rdesk_renegotiation(
                        peer_connection.clone(),
                        node_context.clone(),
                        handler.clone(),
                        resource_id.clone(),
                    );
                }
            } else {
                handler
                    .on_log(format!(
                        "❌ RemoteDesktopRequest denied for resource {}: not active or found",
                        resource_id
                    ))
                    .await;
                let _ = node_context
                    .outgoing_tx
                    .send(nodeinnet_p2p::OutboundP2pPayload::UnsignedMessage(
                        P2pMessage::RemoteDesktopResponse {
                            resource_id: resource_id.clone(),
                            success: false,
                            error_msg: Some(
                                "Remote desktop service is inactive or unavailable".to_string(),
                            ),
                            width: None,
                            height: None,
                        },
                    ))
                    .await;
            }
            return;
        } else if let P2pMessage::RemoteDesktopSdpOffer {
            ref resource_id,
            ref sdp,
        } = p2p_msg
        {
            let handler_sdp = handler.clone();
            let peer_conn_sdp = peer_connection.clone();
            let resource_id_cloned = resource_id.clone();
            let sdp_cloned = sdp.clone();
            let node_context_sdp = node_context.clone();
            tokio::spawn(async move {
                let _ = handler_sdp
                    .on_log(format!(
                        "📥 Received dynamic SDP Offer for resource {}",
                        resource_id_cloned
                    ))
                    .await;
                let sdp_bytes = match base64::engine::general_purpose::STANDARD.decode(sdp_cloned) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = handler_sdp
                            .on_log(format!("❌ Failed to decode base64 Offer: {}", e))
                            .await;
                        return;
                    }
                };
                let sdp_str = match String::from_utf8(sdp_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = handler_sdp
                            .on_log(format!("❌ Failed to parse UTF8 Offer: {}", e))
                            .await;
                        return;
                    }
                };

                let mut offer_desc = RTCSessionDescription::default();
                offer_desc.sdp_type = RTCSdpType::Offer;
                offer_desc.sdp = sdp_str;

                if let Err(e) = peer_conn_sdp.set_remote_description(offer_desc).await {
                    let _ = handler_sdp
                        .on_log(format!("❌ Failed to set remote Offer: {}", e))
                        .await;
                    return;
                }

                let _ = handler_sdp
                    .on_log("Remote description set. Creating Answer...".to_string())
                    .await;
                match peer_conn_sdp.create_answer(None).await {
                    Ok(answer) => {
                        if let Err(e) = peer_conn_sdp.set_local_description(answer.clone()).await {
                            let _ = handler_sdp
                                .on_log(format!("❌ Failed to set local Answer: {:?}", e))
                                .await;
                            return;
                        }

                        if let Some(local_desc) = peer_conn_sdp.local_description().await {
                            let answer_b64 =
                                base64::engine::general_purpose::STANDARD.encode(local_desc.sdp);

                            let _ = node_context_sdp
                                .outgoing_tx
                                .send(nodeinnet_p2p::OutboundP2pPayload::UnsignedMessage(
                                    P2pMessage::RemoteDesktopSdpAnswer {
                                        resource_id: resource_id_cloned.clone(),
                                        sdp: answer_b64,
                                    },
                                ))
                                .await;
                            let _ = handler_sdp
                                .on_log(format!(
                                    "📤 Sent dynamic SDP Answer for resource {}",
                                    resource_id_cloned
                                ))
                                .await;
                        }
                    }
                    Err(e) => {
                        let _ = handler_sdp
                            .on_log(format!("❌ Failed to create Answer: {}", e))
                            .await;
                    }
                }
            });
            return;
        } else if let P2pMessage::RemoteDesktopSdpAnswer {
            ref resource_id,
            ref sdp,
        } = p2p_msg
        {
            let handler_sdp = handler.clone();
            let peer_conn_sdp = peer_connection.clone();
            let resource_id_cloned = resource_id.clone();
            let sdp_cloned = sdp.clone();
            tokio::spawn(async move {
                let _ = handler_sdp
                    .on_log(format!(
                        "📥 Received dynamic SDP Answer for resource {}",
                        resource_id_cloned
                    ))
                    .await;
                let sdp_bytes = match base64::engine::general_purpose::STANDARD.decode(sdp_cloned) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = handler_sdp
                            .on_log(format!("❌ Failed to decode base64 Answer: {}", e))
                            .await;
                        return;
                    }
                };
                let sdp_str = match String::from_utf8(sdp_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = handler_sdp
                            .on_log(format!("❌ Failed to parse UTF8 Answer: {}", e))
                            .await;
                        return;
                    }
                };

                let mut answer_desc = RTCSessionDescription::default();
                answer_desc.sdp_type = RTCSdpType::Answer;
                answer_desc.sdp = sdp_str;

                if let Err(e) = peer_conn_sdp.set_remote_description(answer_desc).await {
                    let _ = handler_sdp
                        .on_log(format!("❌ Failed to set remote Answer: {}", e))
                        .await;
                } else {
                    let _ = handler_sdp.on_log(format!("🟢 SDP Renegotiation successful! Dynamic video stream negotiated for resource {}", resource_id_cloned)).await;

                    let transceivers = peer_conn_sdp.get_transceivers().await;
                    for (i, tr) in transceivers.iter().enumerate() {
                        let mid = tr.mid().await;
                        let direction = tr.direction();
                        let current_direction = tr.current_direction();
                        let sender = tr.sender().await;
                        let mut has_track = false;
                        if let Some(s) = sender
                            && s.track().await.is_some() {
                                has_track = true;
                            }
                        let _ = handler_sdp.on_log(format!(
                            "🔍 [Transceiver-Diag] Host Transceiver #{}: mid={:?}, direction={:?}, current_direction={:?}, has_track={}",
                            i, mid, direction, current_direction, has_track
                        )).await;
                    }
                }
            });
            return;
        } else if let P2pMessage::RemoteDesktopInput { ref event, .. } = p2p_msg {
            if let Some(provider) = desktop_provider() {
                provider.apply_input(event);
            }
            return;
        }

        handler.on_p2p_message(p2p_msg.clone()).await;

        node_context.process_message(p2p_msg.clone()).await;

        core::handle_core_message(
            p2p_msg,
            handler,
            dc,
            node_context,
            target_node_id,
            last_pong,
            peer_connection,
        )
        .await;
    } else if let Err(err) =
        nodeinnet_p2p::p2p::from_bson_slice::<nodeinnet_p2p::SecuredP2pEnvelope>(msg_data)
    {
        handler
            .on_log(format!(
                "⚠️ [DESERIALIZATION ERROR] WebRTC received {} bytes, but failed to parse BSON: {}",
                msg_data.len(),
                err
            ))
            .await;
    }
}

pub struct WebRtcClient {
    pub peer_connection: Arc<RTCPeerConnection>,
    pub target_node_id: String,
    pub connection_id: uuid::Uuid,
    my_info: NodeInfo,
    handler: std::sync::Arc<dyn crate::AppEventHandler>,
    pub data_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    pub node_context: NodeContext,
    pub pending_messages: Arc<Mutex<Vec<nodeinnet_p2p::SecuredP2pEnvelope>>>,
    pub private_key: String,
    pub net_tx: tokio_mpsc::Sender<NetCmd>,
    pub created_at: std::time::Instant,
}

impl WebRtcClient {
    pub async fn new(
        handler: std::sync::Arc<dyn crate::AppEventHandler>,
        net_tx: tokio_mpsc::Sender<NetCmd>,
        my_info: NodeInfo,
        target_node_id: String,
        private_key: String,
        turn_credentials: Option<nodeinnet_p2p::rtc::TurnCredentials>,
        config: client_config::AppConfig,
    ) -> Result<Self, webrtc::Error> {
        let connection_id = uuid::Uuid::new_v4();
        let pending_messages = Arc::new(Mutex::new(Vec::new()));

        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(1024);
        let (log_tx, mut log_rx) = tokio::sync::mpsc::channel(1024);

        let (local_evt_tx, mut local_evt_rx) = tokio::sync::mpsc::channel(32);

        let handler_clone_for_events = handler.clone();
        tokio::spawn(async move {
            while let Some(evt) = local_evt_rx.recv().await {
                handler_clone_for_events.on_local_p2p_event(evt).await;
            }
        });

        let node_context = NodeContext::new(out_tx, log_tx, local_evt_tx, my_info.clone(), config);

        let handler_logs = handler.clone();
        tokio::spawn(async move {
            while let Some(log_msg) = log_rx.recv().await {
                handler_logs.on_log(log_msg).await;
            }
        });

        let mut m = webrtc::api::media_engine::MediaEngine::default();
        m.register_default_codecs()
            .expect("Failed to register default codecs");
        let api = APIBuilder::new().with_media_engine(m).build();

        let mut ice_servers = Vec::new();
        let mut turn_msg = String::new();

        if let Some(turn) = &turn_credentials {
            turn_msg.push_str(&format!(
                "turn:{} (username: {})",
                turn.uris.join(", "),
                turn.username
            ));
            ice_servers.push(RTCIceServer {
                urls: turn.uris.clone(),
                username: turn.username.clone(),
                credential: turn.credential.clone(),
                ..Default::default()
            });
        } else {
            turn_msg.push_str("stun:stun.l.google.com:19302 (Fallback STUN only)");
            ice_servers.push(RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                ..Default::default()
            });
        }
        handler
            .on_log(format!(
                "🧊 [WebRTC Config] Configured ICE Servers: {}",
                turn_msg
            ))
            .await;

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        let peer_connection = Arc::new(api.new_peer_connection(config).await?);

        #[cfg(feature = "feature-rdesk")]
        let pc_track = Arc::downgrade(&peer_connection);
        #[cfg(feature = "feature-rdesk")]
        let handler_track = handler.clone();
        #[cfg(feature = "feature-rdesk")]
        peer_connection.on_track(Box::new(move |track, _receiver| {
            let track_clone = track.clone();
            let pc_weak = pc_track.clone();
            let h = handler_track.clone();
            Box::pin(async move {
                if let Some(t) = track_clone {
                    let _ = h.on_log("📹 WebRTC Media track detected! Initializing H.264 packet depacketizer & decoder...".to_string()).await;
                    let mut decoder = match Decoder::new() {
                        Ok(d) => d,
                        Err(e) => {
                            let _ = h.on_log(format!("❌ Failed to create H.264 decoder: {:?}", e)).await;
                            return;
                        }
                    };
                    let mut depacketizer = H264Packet::default();

                    let mut bgra_buf = Vec::new();
                    let mut accumulated_compressed_size = 0;
                    let track_ssrc = t.ssrc();
                    // Rate-limited so a burst of failures cannot flood the host.
                    let mut last_pli_at = std::time::Instant::now() - std::time::Duration::from_secs(10);

                     loop {
                         if pc_weak.upgrade().is_none() {
                             break;
                         }

                         match t.read_rtp().await {
                             Ok((rtp_packet, _)) => {
                                 accumulated_compressed_size += rtp_packet.payload.len();
                                 match depacketizer.depacketize(&rtp_packet.payload) {
                                     Ok(payload) => {
                                         if !payload.is_empty() {
                                             let mut annex_b = vec![0u8, 0, 0, 1];
                                             annex_b.extend_from_slice(&payload);

                                             match decoder.decode(&annex_b) {
                                             Ok(Some(decoded)) => {
                                                 let dec_w = decoded.width() as usize;
                                                 let dec_h = decoded.height() as usize;

                                                 let y_plane = decoded.y_with_stride();
                                                 let u_plane = decoded.u_with_stride();
                                                 let v_plane = decoded.v_with_stride();
                                                 let y_stride = decoded.y_stride() as usize;
                                                 let u_stride = decoded.u_stride() as usize;
                                                 let v_stride = decoded.v_stride() as usize;

                                                 let target_len = dec_w * dec_h * 4;
                                                 if bgra_buf.len() != target_len {
                                                     bgra_buf = vec![0u8; target_len];
                                                 }

                                                 video_utils::yuv420p_to_bgra(
                                                     y_plane, u_plane, v_plane,
                                                     dec_w, dec_h,
                                                     y_stride, u_stride, v_stride,
                                                     &mut bgra_buf
                                                 );

                                                 let raw_track_id = t.id().await;
                                                 let clean_res_id = raw_track_id.strip_prefix("video-").unwrap_or(&raw_track_id).to_string();

                                                 let current_frame_compressed_size = accumulated_compressed_size;
                                                 accumulated_compressed_size = 0;

                                                 h.on_local_p2p_event(p2p_node::LocalP2pEvent::RemoteDesktopFrame {
                                                     resource_id: clean_res_id,
                                                     bgra_data: bgra_buf.clone(),
                                                     width: dec_w,
                                                     height: dec_h,
                                                     compressed_size: current_frame_compressed_size,
                                                 }).await;
                                             }
                                             Ok(None) => {}
                                             Err(_) => {
                                                 let now = std::time::Instant::now();
                                                 if now.duration_since(last_pli_at) >= std::time::Duration::from_millis(200) {
                                                     last_pli_at = now;
                                                     if let Some(pc) = pc_weak.upgrade() {
                                                         use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
                                                         let pli: Box<dyn webrtc::rtcp::packet::Packet + Send + Sync> = Box::new(PictureLossIndication {
                                                             sender_ssrc: 0,
                                                             media_ssrc: track_ssrc,
                                                         });
                                                         let _ = pc.write_rtcp(&[pli]).await;
                                                         let _ = h.on_log(format!("🔁 [RTCP] Decode failure — sent PLI (keyframe request) for ssrc {}", track_ssrc)).await;
                                                     }
                                                 }
                                             }
                                             }
                                         }
                                     }
                                    Err(_e) => {}
                                }
                            }
                            Err(e) => {
                                let _ = h.on_log(format!("❌ Failed to read RTP packet: {:?}", e)).await;
                                break;
                            }
                        }
                    }
                    let raw_track_id = t.id().await;
                    let clean_res_id = raw_track_id.strip_prefix("video-").unwrap_or(&raw_track_id).to_string();
                    let _ = h.on_local_p2p_event(p2p_node::LocalP2pEvent::RemoteDesktopStopped {
                        resource_id: clean_res_id,
                    }).await;
                    let _ = h.on_log("📹 WebRTC Media track stopped.".to_string()).await;
                }
            })
        }));

        let handler_state = handler.clone();
        let target_node_state = target_node_id.clone();
        let net_tx_state = net_tx.clone();
        let lctx_state = node_context.clone();
        let connection_id_state = connection_id;
        let pc_state = peer_connection.clone();
        let my_id_state = my_info.id.clone();
        peer_connection.on_peer_connection_state_change(Box::new(move |s: webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState| {
            let handler = handler_state.clone();
            let target = target_node_state.clone();
            let net_tx = net_tx_state.clone();
            let lctx = lctx_state.clone();
            let conn_id = connection_id_state;
            let pc = pc_state.clone();
            let my_id = my_id_state.clone();
            Box::pin(async move {
                if s == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::New {
                    return;
                }

                let state = match s {
                    webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Connecting => crate::P2pPeerState::ConnectingTransport,
                    webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Connected => crate::P2pPeerState::ConnectingTransport, // We upgrade to Authenticating via DataChannel
                    webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Disconnected => crate::P2pPeerState::Disconnected,
                    webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Failed => crate::P2pPeerState::Failed,
                    webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Closed => crate::P2pPeerState::Disconnected,
                    _ => crate::P2pPeerState::Disconnected,
                };
                handler.on_log(format!("⚠️ [WebRTC State] Peer {} transport transitioned to {:?}", target, s)).await;
                handler.on_peer_state_changed(target.clone(), state).await;

                if s == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Failed ||
                   s == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Closed
                {
                    handler.on_log(format!("⚠️ Peer {} transport is broken ({:?}). Tearing down session to allow AutoConnect...", target, s)).await;
                    let _ = net_tx.send(crate::NetCmd::DisconnectPeerSession(target.clone(), conn_id)).await;
                    lctx.shutdown().await;
                }

                if s == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Disconnected {
                    let handler_delay = handler.clone();
                    let target_delay = target.clone();
                    let net_tx_delay = net_tx.clone();
                    let lctx_delay = lctx.clone();
                    let pc_delay = pc.clone();
                    let my_id_delay = my_id.clone();
                    tokio::spawn(async move {
                        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                        if pc_delay.connection_state() != RTCPeerConnectionState::Disconnected {
                            return; // recovered on its own — no teardown, session preserved
                        }

                        // Only the smaller node id initiates, so the two never glare.
                        let am_offerer = my_id_delay < target_delay;
                        if am_offerer {
                            let _ = handler_delay.on_log(format!("♻️ [ICE Restart] Peer {} Disconnected — attempting ICE restart (session preserved)", target_delay)).await;
                            let _neg_guard = lctx_delay.negotiation_lock.lock().await;
                            let _ = wait_until_signaling_stable(&pc_delay, tokio::time::Duration::from_secs(5)).await;
                            let opts = webrtc::peer_connection::offer_answer_options::RTCOfferOptions {
                                ice_restart: true,
                                voice_activity_detection: false,
                            };
                            match pc_delay.create_offer(Some(opts)).await {
                                Ok(offer) => {
                                    if pc_delay.set_local_description(offer).await.is_ok()
                                        && let Some(local) = pc_delay.local_description().await {
                                            let envelope = RtcSignalEnvelope {
                                                to_node_id: target_delay.clone(),
                                                signal: RtcSignal::Offer { sdp: local.sdp, ice_restart: true },
                                            };
                                            let _ = net_tx_delay.send(crate::NetCmd::Send(WsMessage::RtcSignal(envelope))).await;
                                        }
                                    let _ = wait_until_signaling_stable(&pc_delay, tokio::time::Duration::from_secs(5)).await;
                                }
                                Err(e) => {
                                    let _ = handler_delay.on_log(format!("❌ [ICE Restart] Failed to create restart offer for {}: {:?}", target_delay, e)).await;
                                }
                            }
                        } else {
                            let _ = handler_delay.on_log(format!("⏳ [ICE Restart] Peer {} Disconnected — awaiting peer's restart offer", target_delay)).await;
                        }

                        tokio::time::sleep(tokio::time::Duration::from_secs(12)).await;
                        let st = pc_delay.connection_state();
                        if st == RTCPeerConnectionState::Disconnected || st == RTCPeerConnectionState::Failed {
                            let _ = handler_delay.on_log(format!("⚠️ Peer {} still {:?} after ICE restart window. Tearing down session to allow AutoConnect...", target_delay, st)).await;
                            let _ = net_tx_delay.send(crate::NetCmd::DisconnectPeerSession(target_delay, conn_id)).await;
                            lctx_delay.shutdown().await;
                        }
                    });
                }
            })
        }));

        let handler_ice = handler.clone();
        let target_node_ice = target_node_id.clone();
        peer_connection.on_ice_connection_state_change(Box::new(
            move |s: webrtc::ice_transport::ice_connection_state::RTCIceConnectionState| {
                let handler = handler_ice.clone();
                let target = target_node_ice.clone();
                Box::pin(async move {
                    handler
                        .on_log(format!(
                            "❄️ [WebRTC ICE State] Peer {} connection state transitioned to {:?}",
                            target, s
                        ))
                        .await;
                })
            },
        ));

        let data_channel_store: Arc<Mutex<Option<Arc<RTCDataChannel>>>> =
            Arc::new(Mutex::new(None));

        let dc_store_for_pipe = data_channel_store.clone();
        let pm_for_pipe = pending_messages.clone();
        let handler_for_our_rx_loop = handler.clone();
        let peer_max_chunk_size = node_context.peer_max_chunk_size.clone();
        let node_context_for_pipe = node_context.clone();
        tokio::spawn(async move {
            while let Some(mut payload) = out_rx.recv().await {
                if let nodeinnet_p2p::OutboundP2pPayload::UnsignedMessage(msg) = payload {
                    let mac = if let Some(res_id) = msg.resource_id() {
                        let mut key_hex = None;
                        for _ in 0..100 {
                            if !node_context_for_pipe
                                .is_authenticated
                                .load(Ordering::Relaxed)
                            {
                                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                                continue;
                            }
                            let session_keys = node_context_for_pipe.session_keys.lock().await;
                            if let Some(k) = session_keys.get(res_id.as_str()) {
                                key_hex = Some(k.clone());
                                break;
                            }
                            drop(session_keys);
                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                        }

                        if let Some(k) = key_hex {
                            if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&msg) {
                                Some(nodeinnet_p2p::crypto::compute_hmac_sha256(&bson_bytes, &k))
                            } else {
                                None
                            }
                        } else {
                            handler_for_our_rx_loop
                                .on_log(format!(
                                    "⏳ Session key for resource {} not found. Dropping packet.",
                                    res_id
                                ))
                                .await;
                            continue;
                        }
                    } else {
                        None
                    };

                    payload = nodeinnet_p2p::OutboundP2pPayload::Message(
                        nodeinnet_p2p::SecuredP2pEnvelope { mac, message: msg },
                    );
                }

                let dc_guard = dc_store_for_pipe.lock().await;
                if let Some(dc) = dc_guard.as_ref()
                    && dc.ready_state()
                        == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
                {
                    match payload {
                        nodeinnet_p2p::OutboundP2pPayload::Message(msg) => {
                            if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&msg) {
                                if !matches!(msg.message, P2pMessage::Ping(_))
                                    && !matches!(msg.message, P2pMessage::Pong(_))
                                {
                                    let hex_str = bson_bytes
                                        .iter()
                                        .take(200)
                                        .map(|b| format!("{:02X}", b))
                                        .collect::<String>();
                                    let _hex_out = if bson_bytes.len() > 200 {
                                        format!(
                                            "{}...[truncated, {} bytes total]",
                                            hex_str,
                                            bson_bytes.len()
                                        )
                                    } else {
                                        hex_str
                                    };

                                    if let Ok(json) = serde_json::to_string(&msg.message) {
                                        let s = if json.len() > 1000 {
                                            format!(
                                                "{}... [truncated]",
                                                json.chars().take(1000).collect::<String>()
                                            )
                                        } else {
                                            json.clone()
                                        };
                                        handler_for_our_rx_loop
                                            .on_log(format!(
                                                "📤 [OUTBOUND-DESERIALIZED] JSON: {}",
                                                s
                                            ))
                                            .await;
                                    }
                                }

                                let s = if bson_bytes.len() > 100 {
                                    format!(
                                        "BSON Packet [truncated, size: {} bytes]",
                                        bson_bytes.len()
                                    )
                                } else {
                                    format!("BSON Packet [size: {} bytes]", bson_bytes.len())
                                };
                                handler_for_our_rx_loop
                                    .on_log(format!("📤 [BACKGROUND SEND] {}", s))
                                    .await;
                                let max_c = peer_max_chunk_size.load(Ordering::Relaxed);
                                let res = send_chunked_binary(
                                    dc,
                                    &bson_bytes,
                                    max_c,
                                    &handler_for_our_rx_loop,
                                    &node_context_for_pipe.dc_write_lock,
                                )
                                .await;
                                if let Err(e) = res {
                                    handler_for_our_rx_loop
                                        .on_log(format!("❌ [SEND ERROR] WebRTC Error: {}", e))
                                        .await;
                                }
                            } else if let Err(e) = nodeinnet_p2p::p2p::to_bson_vec(&msg) {
                                handler_for_our_rx_loop.on_log(format!("❌ [BSON ERROR] Failed to serialize message for sending: {}", e)).await;
                            }
                        }
                        nodeinnet_p2p::OutboundP2pPayload::Binary(b) => {
                            let max_c = peer_max_chunk_size.load(Ordering::Relaxed);
                            let max_c = if max_c == 0 { 10240 } else { max_c };
                            let _ = send_chunked_binary(
                                dc,
                                &b,
                                max_c,
                                &handler_for_our_rx_loop,
                                &node_context_for_pipe.dc_write_lock,
                            )
                            .await;
                        }
                        nodeinnet_p2p::OutboundP2pPayload::UnsignedMessage(_) => {
                            unreachable!(
                                "UnsignedMessage should have been converted to Message by now"
                            );
                        }
                    }
                    continue;
                }

                if let nodeinnet_p2p::OutboundP2pPayload::Message(msg) = payload {
                    pm_for_pipe.lock().await.push(msg);
                }
            }
        });

        let net_tx_ice = net_tx.clone();
        let target_ice = target_node_id.clone();
        peer_connection.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
            let net_tx = net_tx_ice.clone();
            let target = target_ice.clone();
            Box::pin(async move {
                if let Some(candidate) = c
                    && let Ok(json) = candidate.to_json()
                {
                    let envelope = RtcSignalEnvelope {
                        to_node_id: target,
                        signal: RtcSignal::IceCandidate {
                            candidate: json.candidate,
                            sdp_mid: json.sdp_mid,
                            sdp_mline_index: json.sdp_mline_index,
                        },
                    };
                    let _ = net_tx
                        .send(NetCmd::Send(WsMessage::RtcSignal(envelope)))
                        .await;
                }
            })
        }));

        let handler_dc = handler.clone();
        let dc_store_clone = data_channel_store.clone();
        let node_ctx_dc = node_context.clone();
        let pending_msgs_dc = pending_messages.clone();
        let target_node_dc = target_node_id.clone();
        let last_pong = Arc::new(AtomicU64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        ));
        let last_pong_dc = last_pong.clone();
        let my_info_dc_msg = my_info.clone();
        let _private_key_dc = private_key.clone();
        let private_key_dc = private_key.clone();
        let net_tx_dc = net_tx.clone();
        let connection_id_dc = connection_id;

        let peer_conn_dc = peer_connection.clone();
        peer_connection.on_data_channel(Box::new(move |d: Arc<RTCDataChannel>| {
            let peer_conn_for_dc = peer_conn_dc.clone();
            let handler = handler_dc.clone();
            let dc_store = dc_store_clone.clone();
            let d_clone_msg = d.clone();
            let d_clone = d.clone();
            let handler_msg = handler.clone();
            let target_node_msg = target_node_dc.clone();
            let last_pong_msg = last_pong_dc.clone();
            let ctx_msg = node_ctx_dc.clone();
            let net_tx_msg = net_tx_dc.clone();
            let connection_id_dc_inner = connection_id_dc;

            let d_store_async = d.clone();
            let dc_store_clone_for_task = dc_store.clone();
            tokio::spawn(async move {
                *dc_store_clone_for_task.lock().await = Some(d_store_async);
            });



            d.on_message({
                let handler_msg = handler_msg.clone();
                let dc_pong = d_clone_msg.clone();
                let target_node_msg = target_node_msg.clone();
                let pong_ref = last_pong_msg.clone();
                let lctx = ctx_msg.clone();
                let net_tx_msg = net_tx_msg.clone();
                let peer_conn_task = peer_conn_for_dc.clone();
                let connection_id_task = connection_id_dc_inner;

                let (rx_tx, mut rx_rx) = tokio_mpsc::unbounded_channel::<bytes::Bytes>();

                let net_tx_task = net_tx_msg.clone();
                tokio::spawn(async move {
                    let mut assembler = chunking::ChunkAssembler::new();
                    let msg_ctx = IncomingP2pContext {
                        handler: handler_msg.clone(),
                        dc: dc_pong,
                        node_context: lctx.clone(),
                        target_node_id: target_node_msg,
                        last_pong: pong_ref,
                        net_tx: net_tx_task,
                        peer_connection: peer_conn_task,
                        connection_id: connection_id_task,
                    };

                    while let Some(data) = rx_rx.recv().await {
                        let max_c = lctx.peer_max_chunk_size.load(Ordering::Relaxed);
                        match assembler.push(&data, max_c) {
                            chunking::ChunkOutcome::Complete(full_data) => {
                                handle_incoming_p2p_message(&full_data, msg_ctx.clone()).await;
                            }
                            chunking::ChunkOutcome::Incomplete | chunking::ChunkOutcome::Ignored => {}
                            chunking::ChunkOutcome::TooSmall(n) => {
                                handler_msg.on_log(format!("⚠️ [ERROR] Chunk is too small ({} bytes)", n)).await;
                            }
                            chunking::ChunkOutcome::LengthMismatch { declared, available } => {
                                handler_msg.on_log(format!("❌ [DESERIALIZATION ERROR] chunk_len={} but received {} bytes. Dropping buffer.", declared, available)).await;
                            }
                        }
                    }
                });

                Box::new(move |msg: DataChannelMessage| {
                    let _ = rx_tx.send(msg.data);
                    Box::pin(async move {})
                })
            });

            let handler_open = handler.clone();
            let my_info_open = my_info_dc_msg.clone();
            let d_clone_for_send = d.clone();
            let pending_msgs_open = pending_msgs_dc.clone();
            let target_node_ping = target_node_dc.clone();
            let last_pong_ping = last_pong_dc.clone();
            let private_key_for_open = private_key_dc.clone();
            let dc_write_lock_open = node_ctx_dc.dc_write_lock.clone();
            d.on_open(Box::new(move || {
                let handler = handler_open.clone();
                let my_info = my_info_open.clone();
                let dc = d_clone_for_send.clone();
                let pending_queue = pending_msgs_open.clone();
                let target_node_ping = target_node_ping.clone();
                let last_pong_ping = last_pong_ping.clone();
                let d_private_key_open = private_key_for_open.clone();
                let dc_write_lock = dc_write_lock_open.clone();
                Box::pin(async move {
                    handler.on_log(
                        "🟢 Incoming WebRTC DataChannel Opened! Ready to send & receive."
                            .to_string(),
                    ).await;
                    handler.on_peer_state_changed(target_node_ping.clone(), crate::P2pPeerState::Authenticating).await;

                    let priv_key = d_private_key_open.clone();
                    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                    let signature = nodeinnet_p2p::crypto::sign_p2p_handshake(&priv_key, &my_info.id, &target_node_ping, ts)
                        .unwrap_or_else(|_| "INVALID_SIG".to_string());

                    let local_port = p2p_node::local_mesh::LOCAL_TCP_PORT.load(std::sync::atomic::Ordering::Relaxed);
                    let handshake = P2pMessage::Handshake {
                        node_version: my_info.version.clone(),
                        timestamp_ms: ts,
                        signature,
                        requested_resources: None,
                        max_chunk_size: Some(10240),
                        local_tcp_port: if local_port > 0 { Some(local_port) } else { None },
                        from_node_id: Some(my_info.id.clone()),
                    };
                    let envelope = nodeinnet_p2p::SecuredP2pEnvelope { mac: None, message: handshake };
                    if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&envelope) {
                        let max_c = 10240;
                        let _ = send_chunked_binary(&dc, &bson_bytes, max_c, &handler, &dc_write_lock).await;
                    }

                    let mut queue = pending_queue.lock().await;
                    for msg in queue.drain(..) {
                        if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&msg) {
                            let max_c = 10240;
                            let _ = send_chunked_binary(&dc, &bson_bytes, max_c, &handler, &dc_write_lock).await;
                        }
                    }

                    let dc_ping = dc.clone();
                    let _handler_ping = handler.clone();
                    let dc_write_lock_ping = dc_write_lock.clone();
                    tokio::spawn(async move {
                        let mut interval = tokio::time::interval(std::time::Duration::from_secs(P2P_PING_INTERVAL_SECS));
                        loop {
                            interval.tick().await;
                            if dc_ping.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
                                break;
                            }
                            let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                            if ts - last_pong_ping.load(Ordering::Relaxed) > P2P_PONG_TIMEOUT_MS {
                                handler.on_log(format!("⚠️ P2P connection to {} timed out (no pong).", target_node_ping)).await;
                                let _ = dc_ping.close().await;
                                break;
                            }
                            let envelope = nodeinnet_p2p::SecuredP2pEnvelope { mac: None, message: P2pMessage::Ping(ts) };
                            if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&envelope) {
                                let max_c = 10240;
                                let _ = send_chunked_binary(&dc_ping, &bson_bytes, max_c, &handler, &dc_write_lock_ping).await;
                            }
                        }
                    });
                })
            }));

            let handler_close = handler.clone();
            let target_node_close = target_node_dc.clone();
            let nctx_close = node_ctx_dc.clone();
            let net_tx_close = net_tx_dc.clone();
            let connection_id_close = connection_id_dc;
            d.on_close(Box::new(move || {
                let handler = handler_close.clone();
                let target = target_node_close.clone();
                let ctx = nctx_close.clone();
                let net_tx = net_tx_close.clone();
                let conn_id = connection_id_close;
                Box::pin(async move {
                    handler.on_log(format!("🔴 WebRTC DataChannel Closed for {} (session ID: {}).", target, conn_id)).await;
                    let _ = net_tx.send(crate::NetCmd::DisconnectPeerSession(target, conn_id)).await;
                    ctx.shutdown().await;
                })
            }));

            Box::pin(async move {
                *dc_store.lock().await = Some(d_clone);
            })
        }));

        Ok(Self {
            peer_connection,
            target_node_id,
            connection_id,
            my_info,
            handler,
            data_channel: data_channel_store,
            node_context,
            pending_messages,
            private_key,
            net_tx,
            created_at: std::time::Instant::now(),
        })
    }

    pub async fn create_offer(&self) -> Result<String, webrtc::Error> {
        let data_channel = self
            .peer_connection
            .create_data_channel("nodeinnet_data", None)
            .await?;

        *self.data_channel.lock().await = Some(data_channel.clone());

        let dc_clone_for_send = data_channel.clone();
        let _ui_tx_open = self.handler.clone();
        let my_version = self.my_info.version.clone();
        let my_node_id_open = self.my_info.id.clone();
        let pending_msgs_open = self.pending_messages.clone();
        let target_node_id = self.target_node_id.clone();
        let target_node_ping = target_node_id.clone();
        let last_pong = Arc::new(AtomicU64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        ));
        let last_pong_ping = last_pong.clone();
        let handler_open = self.handler.clone();
        let private_key_for_open = self.private_key.clone();
        let dc_write_lock_open = self.node_context.dc_write_lock.clone();
        data_channel.on_open(Box::new(move || {
            let handler = handler_open.clone();
            let version = my_version.clone();
            let dc = dc_clone_for_send.clone();
            let pending_queue = pending_msgs_open.clone();
            let target_node_ping = target_node_ping.clone();
            let last_pong_ping = last_pong_ping.clone();
            let d_private_key_open = private_key_for_open.clone();
            let dc_write_lock = dc_write_lock_open.clone();
            Box::pin(async move {
                handler
                    .on_log("🟢 WebRTC DataChannel Opened! Ready to send & receive.".to_string())
                    .await;
                handler
                    .on_peer_state_changed(
                        target_node_ping.clone(),
                        crate::P2pPeerState::Authenticating,
                    )
                    .await;
                let priv_key = d_private_key_open.clone();
                let my_id = my_node_id_open.clone();
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let signature = nodeinnet_p2p::crypto::sign_p2p_handshake(
                    &priv_key,
                    &my_id,
                    &target_node_ping,
                    ts,
                )
                .unwrap_or_else(|_| "INVALID_SIG".to_string());

                let local_port =
                    p2p_node::local_mesh::LOCAL_TCP_PORT.load(std::sync::atomic::Ordering::Relaxed);
                let handshake = P2pMessage::Handshake {
                    node_version: version.clone(),
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
                if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&envelope) {
                    let max_c = 10240; // Handshake is always default safe size
                    let _ = send_chunked_binary(&dc, &bson_bytes, max_c, &handler, &dc_write_lock)
                        .await;
                }

                let mut queue = pending_queue.lock().await;
                for msg in queue.drain(..) {
                    if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&msg) {
                        let max_c = 10240; // Until we process peer's handshake response
                        let _ =
                            send_chunked_binary(&dc, &bson_bytes, max_c, &handler, &dc_write_lock)
                                .await;
                    }
                }

                let dc_ping = dc.clone();
                let handler_ping = handler.clone();
                let dc_write_lock_ping = dc_write_lock.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                        P2P_PING_INTERVAL_SECS,
                    ));
                    loop {
                        interval.tick().await;
                        if dc_ping.ready_state()
                            != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
                        {
                            break;
                        }
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        if ts - last_pong_ping.load(Ordering::Relaxed) > P2P_PONG_TIMEOUT_MS {
                            handler
                                .on_log(format!(
                                    "⚠️ P2P connection to {} timed out (no pong).",
                                    target_node_ping
                                ))
                                .await;
                            let _ = dc_ping.close().await;
                            break;
                        }
                        let envelope = nodeinnet_p2p::SecuredP2pEnvelope {
                            mac: None,
                            message: P2pMessage::Ping(ts),
                        };
                        if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&envelope) {
                            let _ = send_chunked_binary(
                                &dc_ping,
                                &bson_bytes,
                                10240,
                                &handler_ping,
                                &dc_write_lock_ping,
                            )
                            .await;
                        }
                    }
                });
            })
        }));

        let pc_clone = self.peer_connection.clone();
        let _ui_tx_msg = self.handler.clone();
        let d_clone_msg = data_channel.clone();
        let target_node_msg = self.target_node_id.clone();
        let pong_ref = last_pong.clone();
        let ctx_msg = self.node_context.clone();
        let handler_msg = self.handler.clone();
        let net_tx_msg = self.net_tx.clone();
        let connection_id_msg = self.connection_id;
        data_channel.on_message({
            let handler_msg = handler_msg.clone();
            let dc_pong = d_clone_msg.clone();
            let target_node_msg = target_node_msg.clone();
            let pong_ref = pong_ref.clone();
            let lctx = ctx_msg.clone();
            let net_tx_msg = net_tx_msg.clone();
            let peer_conn_task = pc_clone.clone();
            let connection_id_task = connection_id_msg;

            let (rx_tx, mut rx_rx) = tokio_mpsc::unbounded_channel::<bytes::Bytes>();

            let net_tx_task = net_tx_msg.clone();
            tokio::spawn(async move {
                let mut assembler = chunking::ChunkAssembler::new();
                let msg_ctx = IncomingP2pContext {
                    handler: handler_msg.clone(),
                    dc: dc_pong,
                    node_context: lctx.clone(),
                    target_node_id: target_node_msg,
                    last_pong: pong_ref,
                    net_tx: net_tx_task,
                    peer_connection: peer_conn_task,
                    connection_id: connection_id_task,
                };

                while let Some(data) = rx_rx.recv().await {
                    let max_c = lctx.peer_max_chunk_size.load(Ordering::Relaxed);
                    match assembler.push(&data, max_c) {
                        chunking::ChunkOutcome::Complete(full_data) => {
                            handle_incoming_p2p_message(&full_data, msg_ctx.clone()).await;
                        }
                        chunking::ChunkOutcome::Incomplete | chunking::ChunkOutcome::Ignored => {}
                        chunking::ChunkOutcome::TooSmall(n) => {
                            handler_msg.on_log(format!("⚠️ [ERROR] Chunk is too small ({} bytes)", n)).await;
                        }
                        chunking::ChunkOutcome::LengthMismatch { declared, available } => {
                            handler_msg.on_log(format!("❌ [DESERIALIZATION ERROR] chunk_len={} but received {} bytes. Dropping buffer.", declared, available)).await;
                        }
                    }
                }
            });

            Box::new(move |msg: DataChannelMessage| {
                let _ = rx_tx.send(msg.data);
                Box::pin(async move {})
            })
        });

        let _ui_tx_close = self.handler.clone();
        let target_node_close = self.target_node_id.clone();
        let ctx_close = self.node_context.clone();
        let handler_close = self.handler.clone();
        let net_tx_close = self.net_tx.clone();
        let connection_id_close = self.connection_id;
        data_channel.on_close(Box::new(move || {
            let handler = handler_close.clone();
            let target = target_node_close.clone();
            let lctx = ctx_close.clone();
            let net_tx = net_tx_close.clone();
            let conn_id = connection_id_close;
            Box::pin(async move {
                handler
                    .on_log(format!(
                        "🔴 WebRTC DataChannel Closed for {} (session ID: {}).",
                        target, conn_id
                    ))
                    .await;
                let _ = net_tx
                    .send(crate::NetCmd::DisconnectPeerSession(target, conn_id))
                    .await;
                lctx.shutdown().await;
            })
        }));

        let offer = self.peer_connection.create_offer(None).await?;

        self.peer_connection
            .set_local_description(offer.clone())
            .await?;

        Ok(offer.sdp)
    }

    pub async fn accept_offer_and_answer(
        &self,
        offer_sdp: String,
    ) -> Result<String, webrtc::Error> {
        let mut offer_desc = RTCSessionDescription::default();
        offer_desc.sdp_type = RTCSdpType::Offer;
        offer_desc.sdp = offer_sdp;

        self.peer_connection
            .set_remote_description(offer_desc)
            .await?;

        let answer = self.peer_connection.create_answer(None).await?;
        self.peer_connection
            .set_local_description(answer.clone())
            .await?;

        Ok(answer.sdp)
    }

    pub async fn get_remote_resource_id(
        &self,
        res_type: &nodeinnet_p2p::p2p::ResourceType,
    ) -> Option<String> {
        let maps = self.node_context.remote_resources.lock().await;
        maps.get(res_type).cloned()
    }

    pub async fn apply_answer(&self, answer_sdp: String) -> Result<(), webrtc::Error> {
        let mut answer_desc = RTCSessionDescription::default();
        answer_desc.sdp_type = RTCSdpType::Answer;
        answer_desc.sdp = answer_sdp;

        self.peer_connection
            .set_remote_description(answer_desc)
            .await
    }

    pub async fn add_ice_candidate(
        &self,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    ) -> Result<(), webrtc::Error> {
        let stripped = candidate.strip_prefix("candidate:").unwrap_or(&candidate);
        let parts: Vec<&str> = stripped.split_whitespace().collect();
        if parts.len() >= 6 {
            let ip = parts[4].to_string();
            if ip.parse::<std::net::IpAddr>().is_ok() {
                let mut ips = self.node_context.discovered_ips.lock().await;
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }

        let init = RTCIceCandidateInit {
            candidate,
            sdp_mid,
            sdp_mline_index,
            username_fragment: None, // Usually not needed with Trickle ICE
        };
        self.peer_connection.add_ice_candidate(init).await
    }

    pub async fn send_p2p_message(&self, msg: P2pMessage) -> Result<(), String> {
        let p2p_str = format!("{:?}", msg);
        let msg_log = if p2p_str.len() > 100 {
            format!(
                "{}... [truncated]",
                p2p_str.chars().take(100).collect::<String>()
            )
        } else {
            p2p_str.clone()
        };
        self.handler
            .on_log(format!("📦 [QUEUED] Message queued: {}", msg_log))
            .await;

        let _ = self
            .node_context
            .outgoing_tx
            .send(nodeinnet_p2p::OutboundP2pPayload::UnsignedMessage(msg))
            .await;
        Ok(())
    }

    pub async fn get_connection_type(&self) -> String {
        let mut conn_type = get_connection_type_from_pc(&self.peer_connection).await;
        if conn_type == "P2P" {
            let has_tunnel = {
                if let Some(tunnels) = p2p_node::local_mesh::ACTIVE_TCP_TUNNELS.get() {
                    tunnels.lock().await.contains_key(&self.target_node_id)
                } else {
                    false
                }
            };
            if has_tunnel {
                conn_type = "Local Mesh".to_string();
            }
        }
        conn_type
    }
}

pub async fn get_connection_type_from_pc(
    peer_connection: &webrtc::peer_connection::RTCPeerConnection,
) -> String {
    let stats = peer_connection.get_stats().await;
    let mut active_pair = None;
    for (_, report) in stats.reports.iter() {
        if let webrtc::stats::StatsReportType::CandidatePair(pair_stats) = report
            && format!("{:?}", pair_stats.state) == "Succeeded" {
                if pair_stats.nominated {
                    active_pair = Some(pair_stats);
                    break;
                }
                active_pair = Some(pair_stats);
            }
    }

    if let Some(pair) = active_pair {
        let local_cand = stats.reports.get(&pair.local_candidate_id);
        let remote_cand = stats.reports.get(&pair.remote_candidate_id);
        if let (
            Some(webrtc::stats::StatsReportType::LocalCandidate(local)),
            Some(webrtc::stats::StatsReportType::RemoteCandidate(remote)),
        ) = (local_cand, remote_cand)
        {
            let local_type = format!("{:?}", local.candidate_type);
            let remote_type = format!("{:?}", remote.candidate_type);
            if local_type == "Relay" || remote_type == "Relay" {
                return "Relay".to_string();
            } else {
                return "P2P".to_string();
            }
        }
    }
    "checking".to_string()
}

pub fn spawn_connection_type_poller(
    peer_connection: Arc<webrtc::peer_connection::RTCPeerConnection>,
    target_node_id: String,
    handler: std::sync::Arc<dyn crate::AppEventHandler>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut last_type = String::new();
        loop {
            interval.tick().await;
            let state = peer_connection.connection_state();
            if state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Closed
                || state == webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Failed
            {
                break;
            }
            let mut conn_type = get_connection_type_from_pc(&peer_connection).await;
            if conn_type == "P2P" {
                let has_tunnel = {
                    if let Some(tunnels) = p2p_node::local_mesh::ACTIVE_TCP_TUNNELS.get() {
                        tunnels.lock().await.contains_key(&target_node_id)
                    } else {
                        false
                    }
                };
                if has_tunnel {
                    conn_type = "Local Mesh".to_string();
                }
            }
            if conn_type != "checking" && conn_type != last_type {
                last_type = conn_type.clone();
                let stats = peer_connection.get_stats().await;
                let mut candidate_info = String::new();
                let mut active_pair = None;
                for (_, report) in stats.reports.iter() {
                    if let webrtc::stats::StatsReportType::CandidatePair(pair_stats) = report
                        && format!("{:?}", pair_stats.state) == "Succeeded" {
                            active_pair = Some(pair_stats);
                            if pair_stats.nominated {
                                break;
                            }
                        }
                }
                if let Some(pair) = active_pair {
                    let local_cand = stats.reports.get(&pair.local_candidate_id);
                    let remote_cand = stats.reports.get(&pair.remote_candidate_id);
                    if let (
                        Some(webrtc::stats::StatsReportType::LocalCandidate(local)),
                        Some(webrtc::stats::StatsReportType::RemoteCandidate(remote)),
                    ) = (local_cand, remote_cand)
                    {
                        candidate_info = format!(
                            " (Local: {:?} [ip={:?}, port={:?}], Remote: {:?} [ip={:?}, port={:?}])",
                            local.candidate_type,
                            local.ip,
                            local.port,
                            remote.candidate_type,
                            remote.ip,
                            remote.port
                        );
                    }
                }
                handler
                    .on_log(format!(
                        "❄️ [WebRTC ICE Type] Connection type for {} changed to: {}{}",
                        target_node_id, conn_type, candidate_info
                    ))
                    .await;
                handler
                    .on_peer_connection_type_changed(target_node_id.clone(), conn_type)
                    .await;
            }
        }
    });
}

#[cfg(feature = "feature-rdesk")]
impl Drop for WebRtcClient {
    fn drop(&mut self) {
        let pc = self.peer_connection.clone();
        let conn_id = self.connection_id;
        let _node_id = self.target_node_id.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut streams = active_streams().lock().await;
                let to_stop: Vec<_> = streams
                    .keys()
                    .filter(|(c_id, _)| *c_id == conn_id)
                    .cloned()
                    .collect();

                let mut orig_sizes = active_original_sizes().lock().await;
                let mut bitrates = active_bitrates().lock().await;

                for key in to_stop {
                    orig_sizes.remove(&key);
                    bitrates.remove(&key);
                    if let Some((stop_flag, join_handle, rtp_sender)) = streams.remove(&key) {
                        stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                        join_handle.abort();
                        let _ = pc.remove_track(&rtp_sender).await;
                    }
                }
            });
        } else {
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async {
                        let mut streams = active_streams().lock().await;
                        let to_stop: Vec<_> = streams
                            .keys()
                            .filter(|(c_id, _)| *c_id == conn_id)
                            .cloned()
                            .collect();

                        let mut orig_sizes = active_original_sizes().lock().await;
                        let mut bitrates = active_bitrates().lock().await;

                        for key in to_stop {
                            orig_sizes.remove(&key);
                            bitrates.remove(&key);
                            if let Some((stop_flag, join_handle, rtp_sender)) = streams.remove(&key)
                            {
                                stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                                join_handle.abort();
                                let _ = pc.remove_track(&rtp_sender).await;
                            }
                        }
                    });
                }
            });
        }
    }
}
