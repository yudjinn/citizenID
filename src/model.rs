use core::fmt;
use std::ops::Add;

use anyhow::{anyhow, Error, Result};

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Validation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use uuid::Uuid;

use crate::utils::ApiResponse;
use crate::KEYS;
use crate::{db_handler, utils::hash_password};

pub trait Model {
    const TABLE: &'static str;
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum TokenVersion {
    #[default]
    V1,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ApprovedApplication {
    pub id: Uuid,
    pub user_id: Uuid,
    pub app_id: Uuid,
    pub app_name: String,
    pub scopes: Scopes,
}

impl Model for ApprovedApplication {
    const TABLE: &'static str = "corvus_approvals";
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub app_id: Uuid,
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
    pub app_id: Uuid,
    pub valid: bool,
    pub family: Uuid,
    pub scopes: Vec<Scope>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    pub version: TokenVersion,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
    pub app_id: Uuid,
}

impl From<RefreshToken> for RefreshTokenDB {
    fn from(value: RefreshToken) -> Self {
        let id = value.hash();
        RefreshTokenDB {
            id,
            app_id: value.app_id,
            user_id: value.user_id,
            family: value.family,
            scopes: value.scopes,
            valid: value.valid,
            exp: value.exp,
            version: value.version,
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
}

impl RefreshToken {
    pub fn hash(&self) -> String {
        let mut obj = String::new();
        obj += &self.id.to_string();
        obj += &self.user_id.to_string();
        obj += &self.family.to_string();
        for s in &self.scopes {
            obj += &format!("SCOPE.{}", s);
        }
        obj += &self.valid.to_string();
        obj += &self.exp.format("%Y-%m-%d %H:%M:%S").to_string();
        obj += &format!("{:?}", self.version);

        let mut hasher = Sha256::new();
        hasher.update(obj);
        let result = hasher.finalize();
        String::from_utf8_lossy(&result[..]).to_string()
    }

    pub async fn default(user_id: Uuid, scopes: Vec<Scope>, app_id: Uuid) -> Result<Self> {
        RefreshToken::new(user_id, Uuid::new_v4(), scopes, app_id).await
    }

    pub async fn new(
        user_id: Uuid,
        family: Uuid,
        scopes: Vec<Scope>,
        app_id: Uuid,
    ) -> Result<Self> {
        let r = RefreshToken {
            id: Uuid::new_v4(),
            user_id,
            app_id,
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
}

pub type Scopes = Vec<Scope>;

#[derive(Deserialize, Serialize, Clone, EnumIter, PartialEq, Eq, Debug)]
pub enum Scope {
    Invalid,
    GetUserID,
    SetUser,
    GetUserFull,
    GetRSIID,
    SetRSIID,
    GetDiscordID,
    SetDiscordID,
}

impl From<String> for Scope {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "get_user" => Self::GetUserID,
            "get_user_full" => Self::GetUserID,
            "update_user" => Self::SetUser,
            "get_discord" => Self::GetDiscordID,
            "set_discord" => Self::SetDiscordID,
            "get_rsi" => Self::GetRSIID,
            "set_rsi" => Self::SetRSIID,
            _ => Self::Invalid,
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Invalid => write!(f, "invalid"),
            Scope::GetUserID => write!(f, "get_user"),
            Scope::SetUser => write!(f, "set_user"),
            Scope::GetUserFull => write!(f, "get_user_full"),
            Scope::GetRSIID => write!(f, "get_rsi_id"),
            Scope::SetRSIID => write!(f, "set_rsi_id"),
            Scope::GetDiscordID => write!(f, "get_discord_id"),
            Scope::SetDiscordID => write!(f, "set_discord_id"),
        }
    }
}

impl Scope {
    pub fn check_scopes(scopes: &Scopes, target: &Scope) -> bool {
        if scopes.contains(&Scope::Invalid) {
            return false;
        }
        scopes.contains(target)
    }

    pub async fn check_user_app_relationship(user_id: Uuid, app_id: Uuid) -> Result<Vec<Self>> {
        match db_handler::get_all_from_table_with_filter_by_index::<ApprovedApplication>(
            "user_id",
            &user_id.to_string(),
        )
        .await
        {
            Ok(recs) => {
                for r in recs {
                    if r.app_id == app_id {
                        return Ok(r.scopes);
                    }
                }
                Err(Error::msg(format!("Could not find record for {}", app_id)))
            }
            Err(_) => Err(Error::msg(format!("Could not find record for {}", user_id))),
        }
    }

    pub fn all() -> Vec<Scope> {
        Self::iter().filter(|t| t != &Scope::Invalid).collect()
    }

    pub async fn get_scopes_from_token(token_str: &str) -> Result<Scopes> {
        let t = AuthToken::from_header_str(token_str).await?;
        Ok(t.scopes)
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct AuthToken {
    pub user_id: Uuid,
    pub scopes: Vec<Scope>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
}

impl AuthToken {
    pub async fn default(token: &RefreshToken) -> Self {
        Self {
            user_id: token.user_id.to_owned(),
            scopes: token.scopes.to_owned(),
            exp: Utc::now().add(chrono::Duration::minutes(30)),
        }
    }

    pub async fn from_header_str(s: &str) -> Result<Self> {
        match decode::<Self>(s, &KEYS.decoding, &Validation::default()) {
            Ok(d) => Ok(d.claims),
            Err(e) => Err(anyhow::Error::msg(format!("Could not decode token: {}", e))),
        }
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

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct RSILinkUser {
    pub id: Uuid,
    pub sentinel: String,
}

impl From<User> for RSILinkUser {
    fn from(value: User) -> Self {
        Self {
            id: value.id,
            sentinel: value.sentinel,
        }
    }
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
        let sentinel = Self::generate_sentinel(id).await;
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

    pub async fn generate_sentinel(id: Uuid) -> String {
        let mut hasher = Sha256::new();
        hasher.update(String::from_utf8_lossy(id.as_fields().3).into_owned());
        hasher.update(id.as_fields().1.to_string());
        hasher.update(id.as_fields().2.to_string());
        let result = hasher.finalize();
        let mut s = format!("{:X}", &result);
        s = s[..10].to_string();
        format!("[corvus::{}]", &s)
    }

    pub async fn new_from_discord(snowflake: &str) -> Self {
        let id = Uuid::new_v4();
        let sentinel = Self::generate_sentinel(id).await;
        Self {
            id,
            email: None,
            hashed_password: None,
            salt: None,
            rsi_id: None,
            sentinel,
            status: UserStatus::WaitingValidation,
            discord_sf: Some(snowflake.into()),
        }
    }

    pub async fn get_auth_user(auth_token: &str) -> Result<Option<Self>> {
        match AuthToken::from_header_str(auth_token).await {
            Ok(at) => {
                db_handler::get_item_from_table_with_filter_by_id::<User>(&at.user_id.to_string())
                    .await
            }
            Err(_) => Err(anyhow::Error::msg("Token is invalid.")),
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

impl UpdateUser {
    pub async fn is_valid_payload(&self) -> Result<(), ApiResponse> {
        if self.email.is_some() {
            let re = Regex::new(r"^[^@\s]*?@[^@\s]*?\.[^@\s]*$").unwrap();
            if re.captures(self.email.as_ref().unwrap()).is_none() {
                return Err(ApiResponse::MissingData(json!("Invalid email format.")));
            }
        }
        if self.password.is_some()
            && (self.password.as_ref().unwrap().len() < 8
                || self.password.as_ref().unwrap().len() > 20)
        {
            return Err(ApiResponse::MissingData(json!(
                "Password must be between 8-20 characters."
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginUser {
    pub email: Option<String>,
    pub password: Option<String>,
    pub discord_sf: Option<String>,
    pub app_id: Uuid,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateUserEmail {
    pub email: String,
    pub password: String,
}

impl CreateUserEmail {
    pub async fn is_valid_payload(&self) -> Result<(), ApiResponse> {
        let re = Regex::new(r"^[^@\s]*?@[^@\s]*?\.[^@\s]*$").unwrap();
        if re.captures(&self.email).is_none() {
            return Err(ApiResponse::MissingData(json!("Invalid email format.")));
        }
        if self.password.len() < 8 || self.password.len() > 20 {
            return Err(ApiResponse::MissingData(json!(
                "Password must be between 8-20 characters."
            )));
        }
        Ok(())
    }
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
    pub async fn new_from_template(template: &CreateApplication, user_id: Uuid) -> Result<Self> {
        for uri in &template.callback_uris {
            if uri.parse::<http::Uri>().is_err() {
                return Err(anyhow!("Invalid uri: {}", &uri));
            }
        }
        Ok(Self {
            id: Uuid::new_v4(),
            name: template.name.clone(),
            user_id,
            secret: Uuid::new_v4().to_string(),
            callback_uris: template.callback_uris.clone(),
            status: AppStatus::Active,
        })
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
            name: value.name,
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
    pub name: String,
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

#[derive(Deserialize, Serialize, Clone)]
pub struct AuthReview {
    pub app_id: Uuid,
    pub app_name: String,
    pub user_id: Uuid,
    pub scopes: Scopes,
    pub redirect_uri: String,
    pub state: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct DiscordTokenLogin {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u32,
    pub refresh_token: String,
    pub scope: String,
    pub app_id: Uuid,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct DiscordUserResponse {
    pub id: String,
    pub username: String,
    pub discriminator: String,
    pub avatar: String,
    pub verified: bool,
    pub email: String,
    pub flags: u32,
    pub banner: String,
    pub accent_color: u32,
    pub premium_type: u32,
    pub public_flags: u32,
}
