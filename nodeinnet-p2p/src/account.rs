//! node.in.net account and session types — the REST contract between a client
//! and the service (registration, login, token refresh, device list).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One registered device of a user, with its shared resources as BSON bytes.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub resources: Vec<u8>, // BSON bytes
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub last_used: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub login: String,
    pub node_name: String,
    #[serde(default)]
    pub premium: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub login: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginRequest {
    pub login: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub devices: Vec<Device>,
    pub session_id: String,
    pub ws_url: String,
    #[serde(default)]
    pub turn: Option<crate::rtc::TurnCredentials>,
    #[serde(default)]
    pub premium: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub devices: Vec<Device>,
    pub ws_url: String,
    #[serde(default)]
    pub turn: Option<crate::rtc::TurnCredentials>,
    #[serde(default)]
    pub premium: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorResponse {
    pub msg: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EditRequest {
    pub username: String,
    pub email: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_refresh_response() {
        let json_text = r#"{"access_token":"eyJ","refresh_token":"64c","ws_url":"wss://test","devices":[{"id":"59f","name":"VM","resources":[123,34,102],"created_at":"2026-04-06T22:58:26.064451950Z"}]}"#;
        let res = serde_json::from_str::<RefreshResponse>(json_text);
        assert!(res.is_ok(), "Parse failed: {:?}", res.err());
    }
}
