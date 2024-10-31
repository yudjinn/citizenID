use anyhow::{Error, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::model::{AuthToken, RefreshToken, Scope};

pub async fn hash_password(password: &str) -> Result<(String, String)> {
    let salt = SaltString::generate(&mut OsRng);
    hash_string_enc(password, salt).await
}

pub async fn hash_string_enc(val: &str, salt: SaltString) -> Result<(String, String)> {
    let argon = Argon2::default();
    if let Ok(hashed) = argon.hash_password(format!("{}{}", val, salt).as_bytes(), &salt) {
        Ok((hashed.to_string(), salt.to_string()))
    } else {
        Err(Error::msg("Failed to hash password."))
    }
}

pub fn check_hash(hash_string: &str, salt: &str, comp_string: &str) -> Result<bool> {
    let argon = Argon2::default();
    if let Ok(salt_str) = SaltString::from_b64(salt) {
        if let Ok(hashed) =
            argon.hash_password(format!("{}{}", hash_string, salt).as_bytes(), &salt_str)
        {
            Ok(hashed.to_string() == comp_string)
        } else {
            Err(Error::msg("Failed to hash password."))
        }
    } else {
        Err(Error::msg("Failed to parse hash."))
    }
}

pub async fn generate_token_pair(
    user_id: Uuid,
    app_id: Uuid,
    family: Option<Uuid>,
    scopes: Vec<Scope>,
) -> Result<(RefreshToken, AuthToken)> {
    let r = if family.is_some() {
        RefreshToken::new(user_id, family.unwrap(), scopes, app_id).await?
    } else {
        RefreshToken::default(user_id, scopes, app_id).await?
    };
    let a = AuthToken::default(&r).await;
    Ok((r, a))
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ApiResponse {
    Unauthorized,
    NotFound,
    MissingData(Value),
    InternalServerError,
    InternalServerErrorWithMessage(Error),
    NotImplemented,
    ResourceExists,
    Success(Value),
}

impl From<ApiResponse> for u16 {
    fn from(val: ApiResponse) -> Self {
        match val {
            ApiResponse::Unauthorized => 401,
            ApiResponse::NotFound => 404,
            ApiResponse::MissingData(_) => 400,
            ApiResponse::InternalServerError => 500,
            ApiResponse::InternalServerErrorWithMessage(_) => 500,
            ApiResponse::NotImplemented => 501,
            ApiResponse::ResourceExists => 409,
            ApiResponse::Success(_) => 200,
        }
    }
}

#[derive(Serialize, Clone)]
pub struct ApiResponseBody {
    status: u16,
    payload: Value,
}

impl IntoResponse for ApiResponse {
    fn into_response(self) -> axum::response::Response {
        let (status, payload) = match self {
            ApiResponse::Unauthorized => (StatusCode::UNAUTHORIZED, json!("Unauthorized.")),
            ApiResponse::MissingData(ref val) => (StatusCode::PARTIAL_CONTENT, val.clone()),
            ApiResponse::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!("Something happened."),
            ),
            ApiResponse::InternalServerErrorWithMessage(ref e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!(format!("An error occurred: {}", e)),
            ),
            ApiResponse::NotImplemented => (StatusCode::NOT_IMPLEMENTED, json!("Not implemented.")),
            ApiResponse::NotFound => (StatusCode::NOT_FOUND, json!("Not found.")),
            ApiResponse::ResourceExists => (StatusCode::CONFLICT, json!("Resource exists.")),
            ApiResponse::Success(ref v) => (StatusCode::OK, v.clone()),
        };
        let body = ApiResponseBody {
            status: self.into(),
            payload,
        };
        Response::builder()
            .status(status)
            .body(serde_json::to_string_pretty(&body).unwrap_or_default())
            .unwrap()
            .into_response()
    }
}
