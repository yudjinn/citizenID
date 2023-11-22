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

use crate::model::{AuthToken, RefreshToken};

pub async fn hash_password(password: &str) -> Result<(String, String)> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    if let Ok(hashed) = argon.hash_password(format!("{}{}", password, salt).as_bytes(), &salt) {
        Ok((hashed.to_string(), salt.to_string()))
    } else {
        Err(Error::msg("Failed to hash password."))
    }
}

pub async fn check_password(password: &str, salt: &str, db_pass: &str) -> Result<bool> {
    let argon = Argon2::default();
    if let Ok(salt_str) = SaltString::from_b64(salt) {
        if let Ok(hashed) =
            argon.hash_password(format!("{}{}", password, salt).as_bytes(), &salt_str)
        {
            Ok(hashed.to_string() == db_pass)
        } else {
            Err(Error::msg("Failed to hash password."))
        }
    } else {
        Err(Error::msg("Failed to parse hash."))
    }
}

pub async fn generate_token_pair(user_id: Uuid) -> Result<(RefreshToken, AuthToken)> {
    let r = RefreshToken::default(user_id).await?;
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
        };
        Response::builder()
            .status(status)
            .body(message)
            .unwrap()
            .into_response()
    }
}
