use nodeinnet_p2p::p2p::{LaunchableApp, RemoteAppSession};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

pub mod refusal {
    pub const NOT_SUPPORTED: &str = "not_supported";
    pub const NETWORK_OFF: &str = "network_off";
    pub const NO_CONSENT: &str = "no_consent";
    pub const UNKNOWN_APP: &str = "unknown_app";
    pub const UNKNOWN_SESSION: &str = "unknown_session";
    pub const NO_EGRESS: &str = "no_egress";
    pub const TOO_MANY: &str = "too_many";
    pub const SPAWN_FAILED: &str = "spawn_failed";
}

pub trait AppLaunchProvider: Send + Sync {
    fn view(&self, peer_id: &str) -> Option<(Vec<LaunchableApp>, Vec<RemoteAppSession>)>;

    fn launch(
        &self,
        peer_id: &str,
        egress: &str,
        session_id: Uuid,
        app_id: &str,
    ) -> Result<(), &'static str>;

    fn stop(&self, peer_id: &str, session_id: Uuid) -> Result<(), &'static str>;
}

static PROVIDER: OnceLock<Arc<dyn AppLaunchProvider>> = OnceLock::new();

pub fn install_app_launch_provider(
    provider: Arc<dyn AppLaunchProvider>,
) -> Result<(), Arc<dyn AppLaunchProvider>> {
    PROVIDER.set(provider)
}

pub fn app_launch_provider() -> Option<&'static Arc<dyn AppLaunchProvider>> {
    PROVIDER.get()
}
