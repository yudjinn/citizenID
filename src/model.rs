use color_eyre::Result;
use poem_openapi::{Enum, Object};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::hash_password;

pub trait Model<'a> {
    const TABLE: &'a str;
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
    pub id: Uuid,
    pub email: Option<String>,
    #[oai(skip)]
    pub hashed_password: Option<String>,
    #[oai(skip)]
    pub salt: Option<String>,
    #[oai(read_only)]
    pub rsi_id: Option<String>,
    #[oai(skip)]
    pub discord_sf: Option<String>,
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
    const TABLE: &'a str = "users";
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
pub struct App {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret: String,
    pub callback_uris: Vec<String>,
    pub status: UserStatus,
}

impl<'a> Model<'a> for App {
    const TABLE: &'a str = "applications";
}
