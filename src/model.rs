use chrono::{DateTime, Utc};
use color_eyre::Result;
use poem_openapi::{Enum, Object};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::hash_password;

pub trait Model<'a> {
    const TABLE: &'a str;
}

#[derive(Enum, Default, Serialize, Deserialize, Clone)]
pub enum TokenVersion {
    #[default]
    V1,
}

#[derive(Object, Deserialize, Serialize, Clone)]
pub struct Token {
    pub user_id: Uuid,
    pub family: Uuid,
    pub valid: bool,
    pub refresh_token_expire_dt: DateTime<Utc>,
    pub version: TokenVersion,
}

impl Token {
    pub async fn default(user_id: Uuid) -> Self {
        Token {
            user_id,
            family: Uuid::new_v4(),
            valid: true,
            refresh_token_expire_dt: Utc::now(),
            version: TokenVersion::default(),
        }
    }
}

#[derive(Object, Deserialize, Serialize, Clone)]
pub struct AuthLogin {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Enum, Default, Serialize, Deserialize, Clone)]
pub enum UserStatus {
    WaitingValidation,
    Active,
    Inactive,
    #[default]
    Unknown,
}

#[derive(Object, Deserialize, Serialize, Clone)]
pub struct User {
    #[oai(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord_sf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[oai(skip)]
    pub hashed_password: Option<String>,
    pub id: Uuid,
    #[oai(read_only)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsi_id: Option<String>,
    #[oai(skip)]
    pub salt: Option<String>,
    #[oai(read_only)]
    pub sentinel: String,
    #[oai(read_only)]
    pub status: UserStatus,
}

impl User {
    pub async fn new_from_email(email: &str, password: &str) -> Result<Self> {
        let (hashed, salt) = hash_password(password).await?;
        let id = Uuid::new_v4();
        let sentinel = format!(
            "[id::{}{}]",
            &id.as_fields().2.to_string(),
            &id.as_fields().1.to_string()
        );
        Ok(Self {
            id,
            email: Some(email.into()),
            hashed_password: Some(hashed),
            salt: Some(salt),
            rsi_id: None,
            sentinel,
            status: UserStatus::WaitingValidation,
            discord_sf: None,
        })
    }

    pub async fn new_from_discord(snowflake: &str) -> Self {
        let id = Uuid::new_v4();
        let sentinel = String::from_utf8_lossy(id.as_fields().3);
        Self {
            id,
            email: None,
            hashed_password: None,
            salt: None,
            rsi_id: None,
            sentinel: sentinel.to_string(),
            status: UserStatus::WaitingValidation,
            discord_sf: Some(snowflake.into()),
        }
    }
}
impl<'a> Model<'a> for User {
    const TABLE: &'a str = "corvus-users";
}

#[derive(Object, Clone)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub password: Option<String>,
}

#[derive(Object, Clone)]
pub struct LoginUser {
    pub email: Option<String>,
    pub password: Option<String>,
    pub discord_sf: Option<String>,
}

#[derive(Object, Clone, Default)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Object, Clone)]
pub struct CreateUserEmail {
    pub email: String,
    pub password: String,
}

#[derive(Enum, Deserialize, Serialize)]
pub enum AppStatus {
    Active,
    Inactive,
    Unknown,
}

#[derive(Object, Deserialize, Serialize, Clone)]
pub struct Application {
    #[oai(skip)]
    pub id: Uuid,
    #[oai(skip)]
    pub user_id: Uuid,
    #[oai(read_only)]
    pub secret: String,
    pub callback_uris: Vec<String>,
    pub status: UserStatus,
}

impl<'a> Model<'a> for Application {
    const TABLE: &'a str = "corvus-apps";
}
