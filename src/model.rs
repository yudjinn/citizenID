use std::ops::Add;

use anyhow::Result;
use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Validation};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use uuid::Uuid;

use crate::KEYS;
use crate::{db_handler, utils::hash_password};

pub trait Model<'a> {
    const TABLE: &'a str;
}

#[derive(Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum TokenVersion {
    #[default]
    V1,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub scopes: Vec<Scope>,
    pub valid: bool,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    pub version: TokenVersion,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

impl<'a> Model<'a> for RefreshToken {
    const TABLE: &'a str = "corvus_auth";
}

impl RefreshToken {
    pub async fn default(user_id: Uuid, scopes: Vec<Scope>) -> Result<Self> {
        let r = RefreshToken {
            id: Uuid::new_v4(),
            user_id,
            valid: true,
            scopes,
            exp: Utc::now().add(chrono::Duration::hours(4)),
            version: TokenVersion::default(),
        };

        let res = db_handler::put_item::<Self>(r).await?;

        Ok(res)
    }

    pub async fn from_header_str(s: &str) -> Result<Self> {
        match decode::<Self>(s, &KEYS.decoding, &Validation::default()) {
            Ok(d) => Ok(d.claims),
            Err(e) => Err(anyhow::Error::msg(format!("Could not decode token: {}", e))),
        }
    }

    pub async fn invalidate(&mut self) -> Result<()> {
        self.valid = false;
        if db_handler::update_item(self.id, self.to_owned())
            .await
            .is_ok()
        {
            Ok(())
        } else {
            Err(anyhow::Error::msg("Failed to invalidate."))
        }
    }

    pub async fn invalidate_all_for_user(user_id: Uuid) -> Result<()> {
        for mut token in db_handler::get_all_from_table_with_filter_by_index::<Self>(
            "user_id",
            &user_id.to_string(),
        )
        .await?
        {
            token.valid = false;
            let _ = db_handler::update_item(token.id, token.to_owned()).await?;
        }
        Ok(())
    }

    pub async fn invalidate_static(id: Uuid) -> Result<()> {
        if let Ok(Some(mut token)) =
            db_handler::get_item_from_table_with_filter_by_id::<Self>(&id.to_string()).await
        {
            token.valid = false;
            if db_handler::update_item(id, token).await.is_ok() {
                Ok(())
            } else {
                Err(anyhow::Error::msg("Failed to invalidate."))
            }
        } else {
            Err(anyhow::Error::msg("Could not find token."))
        }
    }

    pub async fn is_valid(&self) -> bool {
        Self::is_valid_static(self.id).await
    }

    pub async fn is_valid_static(id: Uuid) -> bool {
        if let Ok(Some(token)) =
            db_handler::get_item_from_table_with_filter_by_id::<Self>(&id.to_string()).await
        {
            if !token.valid {
                return false;
            }
            if token.exp >= Utc::now() {
                return false;
            }

            if token.version != TokenVersion::default() {
                return false;
            }

            true
        } else {
            false
        }
    }
}

#[derive(Deserialize, Serialize, Clone, EnumIter)]
pub enum Scope {
    None,
    GetUser,
}

impl Scope {
    pub fn all() -> Vec<Scope> {
        Self::iter().collect()
    }

    pub async fn get_scopes_from_token(token_str: &str) -> Result<Vec<Self>> {
        let t = AuthToken::from_header_str(token_str).await?;
        Ok(t.scopes)
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct AuthToken {
    pub user_id: Uuid,
    pub family: Uuid,
    pub scopes: Vec<Scope>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
}

impl AuthToken {
    pub async fn default(token: &RefreshToken) -> Self {
        Self {
            user_id: token.user_id.to_owned(),
            family: token.id.to_owned(),
            scopes: token.scopes.to_owned(),
            exp: Utc::now().add(chrono::Duration::hours(2)),
        }
    }

    pub async fn from_header_str(s: &str) -> Result<Self> {
        match decode::<Self>(s, &KEYS.decoding, &Validation::default()) {
            Ok(d) => Ok(d.claims),
            Err(e) => Err(anyhow::Error::msg(format!("Could not decode token: {}", e))),
        }
    }

    pub async fn is_valid(&self) -> bool {
        RefreshToken::is_valid_static(self.family).await
    }
}

#[derive(Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum UserStatus {
    WaitingValidation,
    Active,
    Inactive,
    #[default]
    Unknown,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct User {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord_sf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub hashed_password: Option<String>,
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsi_id: Option<String>,
    pub salt: Option<String>,
    pub sentinel: String,
    pub status: UserStatus,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct UserResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord_sf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsi_id: Option<String>,
    pub sentinel: String,
    pub status: UserStatus,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct OAuthUser {
    pub id: Uuid,
    pub rsi_id: String,
}

impl From<User> for UserResponse {
    fn from(value: User) -> Self {
        Self {
            discord_sf: value.discord_sf,
            email: value.email,
            id: value.id,
            rsi_id: value.rsi_id,
            sentinel: value.sentinel,
            status: value.status,
        }
    }
    // fn from(self) -> UserResponse {
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

    pub async fn get_auth_user(auth_token: &str) -> Result<Option<Self>> {
        match AuthToken::from_header_str(auth_token).await {
            Ok(at) => {
                if let Ok(Some(token)) = db_handler::get_item_from_table_with_filter_by_id::<
                    RefreshToken,
                >(&at.family.to_string())
                .await
                {
                    if token.valid {
                        db_handler::get_item_from_table_with_filter_by_id::<User>(
                            &token.user_id.to_string(),
                        )
                        .await
                    } else {
                        Err(anyhow::Error::msg("Token is invalid."))
                    }
                } else {
                    Err(anyhow::Error::msg("Token not found."))
                }
            }
            Err(e) => Err(e),
        }
    }
}
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("password", &"[redacted]")
            .finish()
    }
}

impl<'a> Model<'a> for User {
    const TABLE: &'a str = "corvus-users";
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginUser {
    pub email: Option<String>,
    pub password: Option<String>,
    pub discord_sf: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateUserEmail {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum AppStatus {
    Active,
    Inactive,
    Unknown,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Application {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret: String,
    pub callback_uris: Vec<String>,
    pub status: AppStatus,
}

impl Application {
    pub async fn new_from_template(template: &CreateApplication, user_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            secret: Uuid::new_v4().to_string(),
            callback_uris: template.callback_uris.clone(),
            status: AppStatus::Active,
        }
    }

    pub async fn from_request(value: ApplicationRequest) -> Result<Self> {
        match db_handler::get_item_from_table_with_filter_by_id::<Self>(&value.id.to_string()).await
        {
            Ok(Some(app)) => {
                if app.secret == value.secret {
                    Ok(app)
                } else {
                    Err(anyhow::Error::msg("Invalid request."))
                }
            }
            _ => Err(anyhow::Error::msg("Application not found.")),
        }
    }
}

impl<'a> Model<'a> for Application {
    const TABLE: &'a str = "corvus-apps";
}

impl From<Application> for ApplicationResponse {
    fn from(value: Application) -> Self {
        Self {
            id: value.id,
            callback_uris: value.callback_uris,
            status: value.status,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ApplicationRequest {
    pub id: Uuid,
    pub secret: String,
    pub request_for: Option<String>,
}

impl ApplicationRequest {
    pub async fn from_header_str(s: &str) -> Result<Self> {
        match decode::<Self>(s, &KEYS.decoding, &Validation::default()) {
            Ok(d) => Ok(d.claims),
            Err(e) => Err(anyhow::Error::msg(format!("Could not decode token: {}", e))),
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ApplicationResponse {
    pub id: Uuid,
    pub callback_uris: Vec<String>,
    pub status: AppStatus,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct CreateApplication {
    pub callback_uris: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct UpdateApplication {
    pub callback_uris: Vec<String>,
    pub status: AppStatus,
}
