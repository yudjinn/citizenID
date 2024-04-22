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
use serde_json::Value;
use uuid::Uuid;

use crate::model::{AuthToken, RefreshToken, Scope};

pub async fn hash_password(password: &str) -> Result<(String, String)> {
    let salt = SaltString::generate(&mut OsRng);
    hash_string(password, salt).await
}

pub async fn hash_string(val: &str, salt: SaltString) -> Result<(String, String)> {
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
    MissingData,
    InternalServerError,
    InternalServerErrorWithMessage(Error),
    NotImplemented,
    ResourceExists,
    Success(Value),
}

impl ToString for ApiResponse {
    fn to_string(&self) -> String {
        match self {
            ApiResponse::Unauthorized => "403",
            ApiResponse::NotFound => "404",
            ApiResponse::MissingData => "400",
            ApiResponse::InternalServerError => "500",
            ApiResponse::InternalServerErrorWithMessage(_) => "500",
            ApiResponse::NotImplemented => "501",
            ApiResponse::ResourceExists => "409",
            ApiResponse::Success(_) => "200",
        }
        .into()
    }
}

#[derive(Serialize, Clone)]
pub struct ApiResponseBody {
    status: String,
    payload: Value,
}

impl IntoResponse for ApiResponse {
    fn into_response(self) -> axum::response::Response {
        let (status, payload) = match self {
            ApiResponse::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized.".to_string()),
            ApiResponse::MissingData => {
                (StatusCode::PARTIAL_CONTENT, "Fields missing.".to_string())
            }
            ApiResponse::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something happened.".to_string(),
            ),
            ApiResponse::InternalServerErrorWithMessage(ref e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("An error occurred: {}", e),
            ),
            ApiResponse::NotImplemented => {
                (StatusCode::NOT_IMPLEMENTED, "Not implemented.".to_string())
            }
            ApiResponse::NotFound => (StatusCode::NOT_FOUND, "Not found.".to_string()),
            ApiResponse::ResourceExists => (StatusCode::CONFLICT, "Resource exists.".to_string()),
            ApiResponse::Success(ref v) => (StatusCode::OK, v.to_string()),
        };
        let body = ApiResponseBody {
            status: self.to_string(),
            payload: payload.into(),
        };
        Response::builder()
            .status(status)
            .body(serde_json::to_string_pretty(&body).unwrap_or_default())
            .unwrap()
            .into_response()
    }
}
