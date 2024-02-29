use anyhow::Result;
use axum::body::Body;
use axum::http::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::post;
use axum::{extract, Json};
use axum::{Extension, Router};
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::model::{AuthToken, LoginUser, Model, RefreshToken, RefreshTokenRequest, Scope, User};
use crate::utils::{generate_token_pair, ApiResponse};
use crate::KEYS;
use crate::{db_handler, utils::check_hash};

// async fn api_checker(req: &Request, api_key: ApiKey) -> Option<User> {
//     let server_key = req.data::<ServerKey>().unwrap();
//     VerifyWithKey::<User>::verify_with_key(api_key.key.as_str(), server_key).ok()
// }

pub fn get_router() -> Router {
    Router::new()
        .route("/logout", post(logout_user))
        .route("/logout_all", post(invalidate_all_tokens))
        .layer(middleware::from_fn(auth_middleware))
        .route("/login/email", post(login_with_email))
        .route("/login/token", post(get_new_token))
}

async fn invalidate_all_tokens(Extension(current_user): Extension<User>) -> ApiResponse {
    match RefreshToken::invalidate_all_for_user(current_user.id).await {
        Ok(_) => ApiResponse::Success,
        _ => ApiResponse::InternalServerError,
    }
}

async fn login_with_email(
    extract::Json(login): extract::Json<LoginUser>,
) -> Result<Json<AuthResponse>, ApiResponse> {
    match login {
        LoginUser {
            email: Some(email),
            password: Some(password),
            ..
        } => {
            match db_handler::get_item_from_table_with_filter_by_index::<User>("email", &email)
                .await
            {
                Ok(Some(user)) => {
                    if user.hashed_password.is_none() || user.salt.is_none() {
                        return Err(ApiResponse::Unauthorized);
                    }
                    if let Ok(v) = check_hash(
                        &password,
                        &user.salt.clone().unwrap(),
                        &user.hashed_password.clone().unwrap(),
                    )
                    .await
                    {
                        if v {
                            let (r, a) = generate_token_pair(user.id, None, Scope::all())
                                .await
                                .map_err(ApiResponse::InternalServerErrorWithMessage)?;
                            let signed_ref_token = encode(&Header::default(), &r, &KEYS.encoding)
                                .map_err(|_| ApiResponse::InternalServerError)?;
                            let signed_auth_token = encode(&Header::default(), &a, &KEYS.encoding)
                                .map_err(|_| ApiResponse::InternalServerError)?;

                            Ok(Json(AuthResponse {
                                auth_token: signed_auth_token,
                                refresh_token: signed_ref_token,
                            }))
                        } else {
                            Err(ApiResponse::Unauthorized)
                        }
                    } else {
                        Err(ApiResponse::InternalServerError)
                    }
                }
                Ok(None) => Err(ApiResponse::Unauthorized),
                Err(_) => Err(ApiResponse::InternalServerError),
            }
        }
        _ => Err(ApiResponse::MissingData),
    }
}

async fn logout_user(req: Request<Body>) -> Result<(), ApiResponse> {
    let auth_header = req
        .headers()
        .get("auth_token")
        .and_then(|h| h.to_str().ok());

    let auth_header = if let Some(auth_header) = auth_header {
        auth_header
    } else {
        return Err(ApiResponse::NotFound);
    };

    let auth_token = AuthToken::from_header_str(auth_header)
        .await
        .map_err(ApiResponse::InternalServerErrorWithMessage)?;

    if let Some(mut refresh_token) =
        db_handler::get_item_from_table_with_filter_by_id::<RefreshToken>(
            &auth_token.family.to_string(),
        )
        .await
        .map_err(ApiResponse::InternalServerErrorWithMessage)?
    {
        // nuke the token
        refresh_token
            .invalidate()
            .await
            .map_err(ApiResponse::InternalServerErrorWithMessage)?;

        println!("3");
        Ok(())
    } else {
        Err(ApiResponse::InternalServerError)
    }
}

async fn get_new_token(
    extract::Json(token): extract::Json<RefreshTokenRequest>,
) -> Result<Json<AuthResponse>, ApiResponse> {
    let token = RefreshToken::from_header_str(&token.refresh_token)
        .await
        .map_err(ApiResponse::InternalServerErrorWithMessage)?;
    match db_handler::get_item_from_table_with_filter_by_id::<RefreshToken>(
        &RefreshToken::to_db(token).await.family,
    )
    .await
    {
        Ok(Some(mut token)) => {
            if token.valid {
                let (r, a) = generate_token_pair(token.user_id, Some(token.family), Scope::all())
                    .await
                    .map_err(|_| ApiResponse::InternalServerError)?;
                token
                    .invalidate()
                    .await
                    .map_err(ApiResponse::InternalServerErrorWithMessage)?;

                let signed_ref_token = encode(&Header::default(), &r, &KEYS.encoding)
                    .map_err(|_| ApiResponse::InternalServerError)?;
                let signed_auth_token = encode(&Header::default(), &a, &KEYS.encoding)
                    .map_err(|_| ApiResponse::InternalServerError)?;

                Ok(Json(AuthResponse {
                    auth_token: signed_auth_token,
                    refresh_token: signed_ref_token,
                }))
            } else {
                Err(ApiResponse::Unauthorized)
            }
        }
        Ok(None) => Err(ApiResponse::Unauthorized),
        Err(_) => Err(ApiResponse::InternalServerError),
    }
}

pub async fn auth_middleware(
    mut req: Request<Body>,
    next: Next<Body>,
) -> Result<Response, ApiResponse> {
    let auth_header = req
        .headers()
        .get("auth_token")
        .and_then(|h| h.to_str().ok());

    let auth_header = if let Some(auth_header) = auth_header {
        auth_header
    } else {
        return Err(ApiResponse::Unauthorized);
    };

    let scopes = match Scope::get_scopes_from_token(auth_header).await {
        Ok(scopes) => scopes,
        _ => {
            return Err(ApiResponse::Unauthorized);
        }
    };

    let user = match User::get_auth_user(auth_header).await {
        Ok(Some(current_user)) => current_user,
        Err(e) => {
            // log this error
            println!("{}", e);
            return Err(ApiResponse::Unauthorized);
        }
        _ => {
            return Err(ApiResponse::InternalServerError);
        }
    };
    req.extensions_mut().insert(user);
    req.extensions_mut().insert(scopes);
    Ok(next.run(req).await)
}

// async fn login_with_discord(&self) -> UserResponse {
//     LoginUser {
//         discord_sf: Some(discord_sf),
//         ..
//     } => {
//         match db_handler::get_item_from_table_with_filter_by_index::<User>(
//             "discord_sf",
//             &discord_sf,
//         )
//         .await
//         {
//             Ok(Some(user)) => UserResponse::Ok(Json(user.clone())),
//             Ok(None) => UserResponse::NotFound,
//             Err(e) => {
//                 UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e)))
//             }
//         }
//     }
//     _ => UserResponse::MissingData,
// }
//     todo!()
// }

#[derive(Clone, Deserialize, Serialize)]
pub struct AuthResponse {
    auth_token: String,
    refresh_token: String,
}

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}
