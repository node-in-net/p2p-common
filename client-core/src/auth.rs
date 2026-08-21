
use nodeinnet_p2p::{RefreshResponse, TurnRegion};
use reqwest::Client;

pub async fn refresh_access_token(
    api_target: &str,
    refresh_token: &str,
    region: TurnRegion,
) -> Result<RefreshResponse, String> {
    let client = Client::new();
    match client
        .post(format!("{}/account/refresh_token", api_target))
        .json(&nodeinnet_p2p::RefreshRequest {
            refresh_token: refresh_token.to_string(),
            region,
        })
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                match serde_json::from_str::<RefreshResponse>(&text) {
                    Ok(login_resp) => Ok(login_resp),
                    Err(e) => Err(format!("Failed to parse response: {}", e)),
                }
            } else {
                Err(format!("Server returned error status: {}", resp.status()))
            }
        }
        Err(e) => Err(format!("Connection error: {}", e)),
    }
}

pub async fn login(
    api_target: &str,
    login: &str,
    password: &str,
    region: TurnRegion,
) -> Result<nodeinnet_p2p::LoginResponse, String> {
    let client = Client::new();
    let resp = client
        .post(format!("{}/account/login", api_target))
        .json(&nodeinnet_p2p::LoginRequest {
            login: login.to_string(),
            password: password.to_string(),
            region,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceProfile {
    pub display_name: Option<String>,
    pub os: Option<String>,
    pub app_type: Option<String>,
    pub version: Option<String>,
    pub resources: Vec<nodeinnet_p2p::SharedResource>,
}

pub async fn register_device(
    api_target: &str,
    access_token: &str,
    node_id: &str,
    profile: &DeviceProfile,
) -> Result<nodeinnet_p2p::Device, String> {
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

const TURN_REGION_KEY: &str = "turn_region";

pub fn turn_region(config: &client_config::AppConfig) -> nodeinnet_p2p::TurnRegion {
    config.get_or_default(TURN_REGION_KEY)
}

pub fn set_turn_region(config: &client_config::AppConfig, region: nodeinnet_p2p::TurnRegion) {
    config.set(TURN_REGION_KEY, region);
    config.save();
}
