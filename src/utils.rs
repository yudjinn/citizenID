use anyhow::{Error, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};
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
pub enum ApiResponse {
    Unauthorized,
    NotFound,
    MissingData,
    InternalServerError,
    InternalServerErrorWithMessage(Error),
    NotImplemented,
    ResourceExists,
    Success,
}

impl IntoResponse for ApiResponse {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiResponse::Unauthorized => (StatusCode::UNAUTHORIZED, Body::from("Unauthorized.")),
            ApiResponse::MissingData => {
                (StatusCode::PARTIAL_CONTENT, Body::from("Fields missing."))
            }
            ApiResponse::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from("Something happened."),
            ),
            ApiResponse::InternalServerErrorWithMessage(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from(format!("An error occurred: {}", e)),
            ),
            ApiResponse::NotImplemented => (StatusCode::NOT_IMPLEMENTED, Body::empty()),
            ApiResponse::NotFound => (StatusCode::NOT_FOUND, Body::from("Not found.")),
            ApiResponse::ResourceExists => (StatusCode::CONFLICT, Body::from("Resource exists.")),
            ApiResponse::Success => (StatusCode::OK, Body::empty()),
        };
        Response::builder()
            .status(status)
            .body(message)
            .unwrap()
            .into_response()
    }
}
