use std::ops::Add;

use anyhow::Result;
use argon2::password_hash::SaltString;

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Validation};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use uuid::Uuid;

use crate::utils::hash_string;
use crate::{db_handler, utils::hash_password};
use crate::{KEYS, SALT, SECRET};

pub trait Model {
    const TABLE: &'static str;
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
    pub family: Uuid,
    pub scopes: Vec<Scope>,
    pub valid: bool,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    pub version: TokenVersion,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RefreshTokenDB {
    pub id: String,
    pub user_id: Uuid,
    pub valid: bool,
    pub family: String,
    pub scopes: Vec<Scope>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    pub version: TokenVersion,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

impl From<RefreshToken> for RefreshTokenDB {
    fn from(value: RefreshToken) -> Self {
        // TODO: need to hash this, uses user id too
        let id = value.id;
        RefreshTokenDB {
            id: id.to_string(),
            user_id: value.user_id,
            family: value.family.to_string(),
            scopes: value.scopes,
            valid: value.valid,
            exp: value.exp,
            version: value.version,
        }
    }
}

impl From<RefreshTokenDB> for RefreshToken {
    fn from(value: RefreshTokenDB) -> Self {
        RefreshToken {
            id: todo!(),
            user_id: todo!(),
            family: todo!(),
            scopes: todo!(),
            valid: todo!(),
            exp: todo!(),
            version: TokenVersion::V1,
        }
    }
}

impl Model for RefreshTokenDB {
    const TABLE: &'static str = "corvus_auth";
}

impl RefreshTokenDB {
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
    pub async fn invalidate(&mut self) -> Result<()> {
        self.valid = false;
        if db_handler::update_item(self.id.to_string(), self.to_owned())
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
            let _ = db_handler::update_item(token.id.clone(), token.to_owned()).await?;
        }
        Ok(())
    }

    pub async fn invalidate_all_for_family(family: Uuid) -> Result<()> {
        for mut token in db_handler::get_all_from_table_with_filter_by_index::<Self>(
            "family",
            &family.to_string(),
        )
        .await?
        {
            token.valid = false;
            let _ = db_handler::update_item(token.id.clone(), token.to_owned()).await?;
        }
        Ok(())
    }

    pub async fn invalidate_static(id: Uuid) -> Result<()> {
        //TODO: hashing stuffs
        let id = id.to_string();
        if let Ok(Some(mut token)) =
            db_handler::get_item_from_table_with_filter_by_id::<Self>(&id).await
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
}

impl RefreshToken {
    pub async fn default(user_id: Uuid, scopes: Vec<Scope>) -> Result<Self> {
        RefreshToken::new(user_id, Uuid::new_v4(), scopes).await
    }

    pub async fn new(user_id: Uuid, family: Uuid, scopes: Vec<Scope>) -> Result<Self> {
        let r = RefreshToken {
            id: Uuid::new_v4(),
            user_id,
            family,
            valid: true,
            scopes,
            exp: Utc::now().add(chrono::Duration::days(7)),
            version: TokenVersion::default(),
        };

        let _res = db_handler::put_item::<RefreshTokenDB>(r.clone().into()).await?;

        Ok(r)
    }

    pub async fn from_header_str(s: &str) -> Result<Self> {
        match decode::<Self>(s, &KEYS.decoding, &Validation::default()) {
            Ok(d) => Ok(d.claims),
            Err(e) => Err(anyhow::Error::msg(format!("Could not decode token: {}", e))),
        }
    }

    pub async fn invalidate(&mut self) -> Result<()> {
        Into::<RefreshTokenDB>::into(self.clone())
            .invalidate()
            .await
    }

    pub async fn invalidate_all_for_user(user_id: Uuid) -> Result<()> {
        RefreshTokenDB::invalidate_all_for_user(user_id).await
    }

    pub async fn invalidate_all_for_family(family: Uuid) -> Result<()> {
        RefreshTokenDB::invalidate_all_for_family(family).await
    }

    pub async fn invalidate_static(id: Uuid) -> Result<()> {
        RefreshTokenDB::invalidate_static(id).await
    }

    pub async fn is_valid(&self) -> bool {
        Self::is_valid_static(self.id).await
    }

    pub async fn is_valid_static(id: Uuid) -> bool {
        RefreshTokenDB::is_valid_static(id).await
    }
}

pub type Scopes = Vec<Scope>;

#[derive(Deserialize, Serialize, Clone, EnumIter, PartialEq, Eq, Debug)]
pub enum Scope {
    Invalid,
    GetUserID,
    GetRSIID,
    GetDiscordID,
    GetUserFull,
}

impl From<String> for Scope {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "user" => Self::GetUserID,
            "discord" => Self::GetDiscordID,
            "rsi" => Self::GetRSIID,
            "full" => Self::GetUserFull,
            _ => Self::Invalid,
        }
    }
}

impl Scope {
    pub fn check_scopes(scopes: &Scopes, target: &Scope) -> bool {
        scopes.contains(target)
    }

    pub fn all() -> Vec<Scope> {
        Self::iter().collect()
    }

    pub async fn get_scopes_from_token(token_str: &str) -> Result<Scopes> {
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
            family: token.family.to_owned(),
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
                if let Ok(Some(token)) = db_handler::get_item_from_table_with_filter_by_index::<
                    RefreshTokenDB,
                >("family", &at.family.to_string())
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

impl Model for User {
    const TABLE: &'static str = "corvus-users";
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
    pub name: String,
    pub secret: String,
    pub callback_uris: Vec<String>,
    pub status: AppStatus,
}

impl Application {
    pub async fn new_from_template(template: &CreateApplication, user_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: template.name.clone(),
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

impl Model for Application {
    const TABLE: &'static str = "corvus-apps";
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
    pub name: String,
    pub callback_uris: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct UpdateApplication {
    pub name: Option<String>,
    pub callback_uris: Option<Vec<String>>,
    pub status: Option<AppStatus>,
}
