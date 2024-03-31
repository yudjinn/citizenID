use anyhow::anyhow;
use anyhow::Result;
use axum::body::Body;
use axum::http::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, post};
use axum::{extract, Json};
use axum::{Extension, Router};
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header};
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::DiscordUserResponse;
use crate::model::{
    Application, ApprovedApplication, DiscordTokenLogin, LoginUser, RefreshToken, RefreshTokenDB,
    RefreshTokenRequest, Scope, Scopes, User,
};
use crate::utils::{generate_token_pair, ApiResponse};
use crate::{db_handler, utils::check_hash};
use crate::{KEYS, MASTER_APP_ID};

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
        .route("/login/discord", post(login_with_discord))
        .route("/login/discord", delete(revoke_discord))
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
            password: Some(entered_password),
            ..
        } => {
            // TODO: pull this into a middleware
            if let Some(app) = db_handler::get_item_from_table_with_filter_by_id::<Application>(
                &login.app_id.to_string(),
            )
            .await
            .unwrap()
            {
                match db_handler::get_item_from_table_with_filter_by_index::<User>("email", &email)
                    .await
                {
                    Ok(Some(user)) => {
                        // if the user doesnt have a password set
                        if user.hashed_password.is_none() || user.salt.is_none() {
                            return Err(ApiResponse::Unauthorized);
                        }
                        match Scope::check_user_app_relationship(user.id, app.id).await {
                            Ok(scopes) => {
                                if let Ok(v) = check_hash(
                                    &entered_password,
                                    user.salt.as_ref().unwrap(),
                                    user.hashed_password.as_ref().unwrap(),
                                ) {
                                    if v {
                                        let (r, a) =
                                            generate_token_pair(user.id, app.id, None, scopes)
                                                .await
                                                .map_err(
                                                    ApiResponse::InternalServerErrorWithMessage,
                                                )?;
                                        let signed_ref_token =
                                            encode(&Header::default(), &r, &KEYS.encoding)
                                                .map_err(|_| ApiResponse::InternalServerError)?;
                                        let signed_auth_token =
                                            encode(&Header::default(), &a, &KEYS.encoding)
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
                            _ => Err(ApiResponse::Unauthorized),
                        }
                    }
                    Ok(None) => Err(ApiResponse::NotFound),
                    Err(_) => Err(ApiResponse::InternalServerError),
                }
            } else {
                Err(ApiResponse::NotFound)
            }
        }
        _ => Err(ApiResponse::MissingData),
    }
}

async fn logout_user(req: Request<Body>) -> Result<ApiResponse, ApiResponse> {
    let refresh_header = req
        .headers()
        .get("refresh_token")
        .and_then(|h| h.to_str().ok());

    let refresh_header = if let Some(refresh_header) = refresh_header {
        refresh_header
    } else {
        return Err(ApiResponse::MissingData);
    };

    let mut refresh_token = RefreshToken::from_header_str(refresh_header)
        .await
        .map_err(ApiResponse::InternalServerErrorWithMessage)?;

    // nuke the token
    refresh_token
        .invalidate()
        .await
        .map_err(ApiResponse::InternalServerErrorWithMessage)?;
    Ok(ApiResponse::Success)
}

async fn login_with_discord(
    Json(token): Json<DiscordTokenLogin>,
) -> Result<Json<AuthResponse>, ApiResponse> {
    // make subcall to `/users/@me`
    let client = reqwest::Client::new();
    let discord_response = client
        .get("https://discord.com/api/users/@me")
        .bearer_auth(token.access_token)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .timeout(tokio::time::Duration::from_secs(5))
        .send()
        .await
        .unwrap()
        .json::<DiscordUserResponse>()
        .await
        .unwrap();

    let snowflake = discord_response.id;

    if let Some(app) =
        db_handler::get_item_from_table_with_filter_by_id::<Application>(&token.app_id.to_string())
            .await
            .unwrap()
    {
        if let Ok(Some(user)) =
            db_handler::get_item_from_table_with_filter_by_index::<User>("discord_sf", &snowflake)
                .await
        {
            match Scope::check_user_app_relationship(user.id, app.id).await {
                Ok(scopes) => {
                    // user exists, login
                    let (r, a) = generate_token_pair(user.id, token.app_id, None, scopes)
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
                }
                Err(_) => Err(ApiResponse::Unauthorized),
            }
        } else {
            // user doesnt exist, create
            let u = User::new_from_discord(&snowflake).await;
            if let Ok(user) = db_handler::put_item::<User>(u).await {
                let aa = ApprovedApplication {
                    id: Uuid::new_v4(),
                    user_id: user.id,
                    app_id: MASTER_APP_ID.to_owned(),
                    app_name: "CORVUS".into(),
                    scopes: Scope::all(),
                };
                match db_handler::put_item::<ApprovedApplication>(aa).await {
                    Ok(aa) => {
                        // user exists, login
                        let (r, a) = generate_token_pair(user.id, token.app_id, None, aa.scopes)
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
                    }
                    Err(_) => Err(ApiResponse::InternalServerErrorWithMessage(anyhow!(
                        "Could not generate access, please contact support with user_id: {}",
                        user.id
                    ))),
                }
            } else {
                Err(ApiResponse::InternalServerError)
            }
        }
    } else {
        Err(ApiResponse::NotFound)
    }
}

async fn revoke_discord(
    Extension(mut current_user): Extension<User>,
    Extension(scopes): Extension<Scopes>,
) -> Result<ApiResponse, ApiResponse> {
    if !Scope::check_scopes(&scopes, &Scope::SetDiscordID) {
        return Err(ApiResponse::Unauthorized);
    }
    if let Some(_sf) = current_user.discord_sf {
        if current_user.email.is_some() && current_user.hashed_password.is_some() {
            current_user.discord_sf = None;
            db_handler::put_item::<User>(current_user)
                .await
                .map_err(ApiResponse::InternalServerErrorWithMessage)?;
            Ok(ApiResponse::Success)
        } else {
            Err(ApiResponse::MissingData)
        }
    } else {
        Err(ApiResponse::NotFound)
    }
}

async fn get_new_token(
    extract::Json(token): extract::Json<RefreshTokenRequest>,
) -> Result<Json<AuthResponse>, ApiResponse> {
    let token = RefreshToken::from_header_str(&token.refresh_token)
        .await
        .map_err(ApiResponse::InternalServerErrorWithMessage)?;
    match db_handler::get_item_from_table_with_filter_by_id::<RefreshTokenDB>(&token.hash()).await {
        Ok(Some(t)) => {
            let mut token = token;
            if t.valid && token.app_id == t.app_id {
                let (r, a) =
                    generate_token_pair(token.user_id, t.app_id, Some(token.family), t.scopes)
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
                // Might be a rewind attack, invalidate family
                RefreshToken::invalidate_all_for_family(token.family)
                    .await
                    .map_err(ApiResponse::InternalServerErrorWithMessage)?;
                Err(ApiResponse::Unauthorized)
            }
        }
        Ok(None) => Err(ApiResponse::Unauthorized),
        Err(_) => Err(ApiResponse::InternalServerError),
    }
}

pub async fn auth_middleware(mut req: Request<Body>, next: Next) -> Result<Response, ApiResponse> {
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
