//! HTTP account authentication — GTK-free, reqwest-only, so headless consumers
//! can share the login/refresh flow without pulling in a UI toolkit.

use nodeinnet_p2p::RefreshResponse;
use reqwest::Client;

/// Refresh the access token (and session metadata: `ws_url`, `turn`, devices)
/// using a refresh token against `{api_target}/account/refresh_token`.
///
/// If the server does not return TURN credentials and a `login` is provided, a
/// fallback `TurnCredentials` is synthesized (login as username, access token as
/// credential) — matching the previous behaviour of both duplicated copies.
pub async fn refresh_access_token(
    api_target: &str,
    refresh_token: &str,
    login: Option<&str>,
) -> Result<RefreshResponse, String> {
    let client = Client::new();
    match client
        .post(format!("{}/account/refresh_token", api_target))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                match serde_json::from_str::<RefreshResponse>(&text) {
                    Ok(mut login_resp) => {
                        if login_resp.turn.is_none() {
                            if let Some(l) = login {
                                login_resp.turn = Some(nodeinnet_p2p::rtc::TurnCredentials {
                                    username: l.to_string(),
                                    credential: login_resp.access_token.clone(),
                                    uris: vec![
                                        "turn:node.in.net:3478".to_string(),
                                        "stun:node.in.net:3478".to_string(),
                                    ],
                                });
                            }
                        }
                        Ok(login_resp)
                    }
                    Err(e) => Err(format!("Failed to parse response: {}", e)),
                }
            } else {
                Err(format!("Server returned error status: {}", resp.status()))
            }
        }
        Err(e) => Err(format!("Connection error: {}", e)),
    }
}

/// Log in with account credentials against `{api_target}/account/login`.
///
/// The caller persists `refresh_token`/`account_login` and decides the UX.
pub async fn login(
    api_target: &str,
    login: &str,
    password: &str,
) -> Result<nodeinnet_p2p::LoginResponse, String> {
    let client = Client::new();
    let resp = client
        .post(format!("{}/account/login", api_target))
        .json(&nodeinnet_p2p::LoginRequest {
            login: login.to_string(),
            password: password.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("Connection error: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("Invalid login or password ({})", resp.status()));
    }
    resp.json::<nodeinnet_p2p::LoginResponse>()
        .await
        .map_err(|e| format!("Failed to parse login response: {}", e))
}

/// Invalidate the account session on the server (`{api_target}/account/logoff`).
/// The endpoint reads the session from cookies (it serves the browser), so the
/// native client replays its stored tokens as a `Cookie` header. Best-effort:
/// callers treat any error as non-fatal — clearing the local token is what makes
/// sign-out real for this client regardless.
pub async fn logoff(
    api_target: &str,
    refresh_token: &str,
    access_token: Option<&str>,
) -> Result<(), String> {
    let mut cookie = format!("RefreshToken={refresh_token}");
    if let Some(at) = access_token {
        cookie.push_str("; AccessToken=");
        cookie.push_str(at);
    }
    let resp = Client::new()
        .post(format!("{}/account/logoff", api_target))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .map_err(|e| format!("Connection error: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("logoff failed ({})", resp.status()));
    }
    Ok(())
}

/// What a device stores about itself on the server, BSON-encoded into
/// `Device.resources`. Field names are wire-compatible with `ResourceWrapper`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceProfile {
    pub display_name: Option<String>,
    pub os: Option<String>,
    pub app_type: Option<String>,
    pub version: Option<String>,
    pub resources: Vec<nodeinnet_p2p::SharedResource>,
}

/// Register (or update — the server upserts by `name`) this device under the
/// account. `node_id` is the server-side device `name`, exactly what the
/// existing apps send; the human-readable name travels inside the profile.
pub async fn register_device(
    api_target: &str,
    access_token: &str,
    node_id: &str,
    profile: &DeviceProfile,
) -> Result<nodeinnet_p2p::Device, String> {
    // Local paths stay on the device.
    let profile = DeviceProfile {
        resources: profile
            .resources
            .iter()
            .map(|r| r.without_config())
            .collect(),
        ..profile.clone()
    };
    let bson_bytes = bson::ser::serialize_to_vec(&profile)
        .map_err(|e| format!("Failed to encode device profile: {}", e))?;
    let client = Client::new();
    let resp = client
        .post(format!("{}/account/devices", api_target))
        .bearer_auth(access_token)
        .json(&serde_json::json!({ "name": node_id, "resources": bson_bytes }))
        .send()
        .await
        .map_err(|e| format!("Connection error: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("Device registration failed ({})", resp.status()));
    }
    resp.json::<nodeinnet_p2p::Device>()
        .await
        .map_err(|e| format!("Failed to parse device response: {}", e))
}
