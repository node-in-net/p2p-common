//! Screen capture and input injection, as seen by the transport.
//!
//! Encoding frames onto a WebRTC track happens here; producing them talks to
//! PipeWire, ScreenCaptureKit or the Windows capture API, which an application
//! supplies via [`install_desktop_provider`]. Without a provider this node
//! cannot share its screen, but still views other peers' screens — decoding
//! lives here.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};

use nodeinnet_p2p::DesktopInputEvent;

/// One captured frame: a raw BGRA pixel buffer and its dimensions.
#[derive(Clone, Debug)]
pub struct CapturedFrame {
    pub data: Vec<u8>,
    pub width: usize,
    pub height: usize,
}

/// Progress of a capture session, reported out of band from the frames.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DesktopStreamStatus {
    Starting(String),
    Active { width: usize, height: usize },
    Error(String),
    Stopped,
}

pub type FrameCallback = Box<dyn Fn(CapturedFrame) + Send + Sync + 'static>;
pub type StatusCallback = Box<dyn Fn(DesktopStreamStatus) + Send + Sync + 'static>;

/// Captures this machine's screen and applies remote input to it.
pub trait DesktopProvider: Send + Sync {
    /// Begin capturing until `stop_flag` is set, invoking `on_frame` per frame.
    /// `force_select` asks the platform to prompt for a source again rather than
    /// reuse a remembered one.
    fn start_capture(
        &self,
        stop_flag: Arc<AtomicBool>,
        force_select: bool,
        on_frame: FrameCallback,
        on_status: StatusCallback,
    );

    /// Size of the primary screen, used to map remote pointer coordinates.
    fn primary_screen_size(&self) -> Option<(usize, usize)>;

    /// Apply one pointer or keyboard event received from a peer.
    fn apply_input(&self, event: &DesktopInputEvent);
}

static DESKTOP_PROVIDER: OnceLock<Arc<dyn DesktopProvider>> = OnceLock::new();

/// Install the provider serving this node's screen. Call once, before
/// connecting; later calls are ignored and return the provider already in place.
pub fn install_desktop_provider(
    provider: Arc<dyn DesktopProvider>,
) -> Result<(), Arc<dyn DesktopProvider>> {
    DESKTOP_PROVIDER.set(provider)
}

/// The installed provider, or `None` when this node never shares its screen.
pub fn desktop_provider() -> Option<&'static Arc<dyn DesktopProvider>> {
    DESKTOP_PROVIDER.get()
}
