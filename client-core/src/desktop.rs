//! Screen capture and input injection, as seen by the transport.  Encoding frames onto.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};

use nodeinnet_p2p::DesktopInputEvent;

#[derive(Clone, Debug)]
pub struct CapturedFrame {
    pub data: Vec<u8>,
    pub width: usize,
    pub height: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DesktopStreamStatus {
    Starting(String),
    Active { width: usize, height: usize },
    Error(String),
    Stopped,
}

pub type FrameCallback = Box<dyn Fn(CapturedFrame) + Send + Sync + 'static>;
pub type StatusCallback = Box<dyn Fn(DesktopStreamStatus) + Send + Sync + 'static>;

pub trait DesktopProvider: Send + Sync {
    fn start_capture(
        &self,
        stop_flag: Arc<AtomicBool>,
        force_select: bool,
        on_frame: FrameCallback,
        on_status: StatusCallback,
    );

    fn primary_screen_size(&self) -> Option<(usize, usize)>;

    fn apply_input(&self, event: &DesktopInputEvent);
}

static DESKTOP_PROVIDER: OnceLock<Arc<dyn DesktopProvider>> = OnceLock::new();

pub fn install_desktop_provider(
    provider: Arc<dyn DesktopProvider>,
) -> Result<(), Arc<dyn DesktopProvider>> {
    DESKTOP_PROVIDER.set(provider)
}

/// The installed provider, or `None` when this node never shares its screen.
pub fn desktop_provider() -> Option<&'static Arc<dyn DesktopProvider>> {
    DESKTOP_PROVIDER.get()
}
