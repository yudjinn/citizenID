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
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::model::ApplicationDB;
use crate::model::AuthSuccessDB;
use crate::model::DiscordUserResponse;
use crate::model::LoginOauth;
use crate::model::UserStatus;
use crate::model::{
    ApprovedApplication, DiscordTokenLogin, LoginUser, RefreshToken, RefreshTokenDB,
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
        .route("/login/oauth", post(login_with_oauth))
        .route("/login/token", post(get_new_token))
        .route("/login/discord", post(login_with_discord))
        .route("/login/discord", delete(revoke_discord))
}

async fn invalidate_all_tokens(Extension(current_user): Extension<User>) -> ApiResponse {
    match RefreshToken::invalidate_all_for_user(current_user.id).await {
        Ok(_) => ApiResponse::Success(json!("Success")),
        _ => ApiResponse::InternalServerError,
    }
}
async fn login_with_oauth(extract::Json(login): extract::Json<LoginOauth>) -> ApiResponse {
    // make sure the secret matches the app
    if let Ok(Some(app)) =
        db_handler::get_item_from_table_with_filter_by_id::<ApplicationDB>(&login.app_id).await
    {
        let mut hasher = Sha256::new();
        hasher.update(login.secret);
        let result = hasher.finalize();
        let sec_hash = String::from_utf8_lossy(&result[..]).to_string();
        if sec_hash != app.secret {
            return ApiResponse::Unauthorized;
        }

        // make sure the code matches the app
        if let Ok(Some(auth_success)) =
            db_handler::get_item_from_table_with_filter_by_id::<AuthSuccessDB>(&login.code).await
        {
            if auth_success.app_id != app.id.to_string() {
                return ApiResponse::Unauthorized;
            }

            // remove the code
            if db_handler::delete_item::<AuthSuccessDB>(auth_success.id.clone())
                .await
                .is_ok()
            {
                // return the token login info
                if let Ok(uid) = Uuid::parse_str(&auth_success.user_id) {
                    if let Ok(scopes) = Scope::check_user_app_relationship(uid, app.id).await {
                        let (r, a) = generate_token_pair(uid, app.id, None, scopes)
                            .await
                            .map_err(ApiResponse::InternalServerErrorWithMessage)
                            .unwrap();
                        let signed_ref_token = encode(&Header::default(), &r, &KEYS.encoding)
                            .map_err(|_| ApiResponse::InternalServerError)
                            .unwrap();
                        let signed_auth_token = encode(&Header::default(), &a, &KEYS.encoding)
                            .map_err(|_| ApiResponse::InternalServerError)
                            .unwrap();

                        return ApiResponse::Success(
                            serde_json::to_value(AuthResponse {
                                auth_token: signed_auth_token,
                                refresh_token: signed_ref_token,
                            })
                            .unwrap(),
                        );
                    }
                }
            }
        }
    }
    ApiResponse::Unauthorized
}

async fn login_with_email(extract::Json(login): extract::Json<LoginUser>) -> ApiResponse {
    match login {
        LoginUser {
            email: Some(email),
            password: Some(entered_password),
            ..
        } => {
            // TODO: pull this into a middleware
            if let Some(app) = db_handler::get_item_from_table_with_filter_by_id::<ApplicationDB>(
                &login.app_id.to_string(),
            )
            .await
            .unwrap()
            {
                match db_handler::get_item_from_table_with_filter_by_index::<User>("email", &email)
                    .await
                {
                    Ok(Some(user)) => {
                        if user.status == UserStatus::Inactive {
                            return ApiResponse::NotFound;
                        }
                        // if the user doesnt have a password set
                        if user.hashed_password.is_none() || user.salt.is_none() {
                            return ApiResponse::Unauthorized;
                        }
                        match Scope::check_user_app_relationship(user.id, app.id).await {
                            Ok(scopes) => {
                                if !Scope::check_scopes(&scopes, &Scope::GetUserFull) {
                                    return ApiResponse::Unauthorized;
                                }
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
                                                )
                                                .unwrap();
                                        let signed_ref_token =
                                            encode(&Header::default(), &r, &KEYS.encoding)
                                                .map_err(|_| ApiResponse::InternalServerError)
                                                .unwrap();
                                        let signed_auth_token =
                                            encode(&Header::default(), &a, &KEYS.encoding)
                                                .map_err(|_| ApiResponse::InternalServerError)
                                                .unwrap();

                                        ApiResponse::Success(
                                            serde_json::to_value(AuthResponse {
                                                auth_token: signed_auth_token,
                                                refresh_token: signed_ref_token,
                                            })
                                            .unwrap(),
                                        )
                                    } else {
                                        ApiResponse::Unauthorized
                                    }
                                } else {
                                    ApiResponse::InternalServerError
                                }
                            }
                            _ => ApiResponse::Unauthorized,
                        }
                    }
                    Ok(None) => ApiResponse::Unauthorized,
                    Err(_) => ApiResponse::InternalServerError,
                }
            } else {
                ApiResponse::NotFound
            }
        }
        _ => ApiResponse::MissingData(json!("Missing either email or password.")),
    }
}

async fn logout_user(req: Request<Body>) -> ApiResponse {
    let refresh_header = req
        .headers()
        .get("refresh_token")
        .and_then(|h| h.to_str().ok());

    let refresh_header = if let Some(refresh_header) = refresh_header {
        refresh_header
    } else {
        return ApiResponse::MissingData(json!("refresh_token required to logout."));
    };

    let mut refresh_token = RefreshToken::from_header_str(refresh_header)
        .await
        .map_err(|_| ApiResponse::Success(json!("Invalid token, nothing to do.")))
        .unwrap();

    // nuke the token
    refresh_token
        .invalidate()
        .await
        .map_err(ApiResponse::InternalServerErrorWithMessage)
        .unwrap();
    ApiResponse::Success(json!("Success"))
}

async fn login_with_discord(Json(token): Json<DiscordTokenLogin>) -> ApiResponse {
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

    if let Some(app) = db_handler::get_item_from_table_with_filter_by_id::<ApplicationDB>(
        &token.app_id.to_string(),
    )
    .await
    .unwrap()
    {
        if let Ok(Some(user)) =
            db_handler::get_item_from_table_with_filter_by_index::<User>("discord_sf", &snowflake)
                .await
        {
            if user.status == UserStatus::Inactive {
                return ApiResponse::NotFound;
            }
            match Scope::check_user_app_relationship(user.id, app.id).await {
                Ok(scopes) => {
                    // user exists, login
                    if !Scope::check_scopes(&scopes, &Scope::GetUserFull) {
                        return ApiResponse::Unauthorized;
                    }
                    let (r, a) = generate_token_pair(user.id, token.app_id, None, scopes)
                        .await
                        .map_err(ApiResponse::InternalServerErrorWithMessage)
                        .unwrap();
                    let signed_ref_token = encode(&Header::default(), &r, &KEYS.encoding)
                        .map_err(|_| ApiResponse::InternalServerError)
                        .unwrap();
                    let signed_auth_token = encode(&Header::default(), &a, &KEYS.encoding)
                        .map_err(|_| ApiResponse::InternalServerError)
                        .unwrap();

                    ApiResponse::Success(
                        serde_json::to_value(AuthResponse {
                            auth_token: signed_auth_token,
                            refresh_token: signed_ref_token,
                        })
                        .unwrap(),
                    )
                }
                Err(_) => ApiResponse::Unauthorized,
            }
        } else {
            // user doesnt exist, create
            let u = User::new_from_discord(&snowflake).await;
            if let Ok(user) = db_handler::put_item::<User>(u).await {
                let mut hasher = Sha256::new();
                hasher.update(format!("{}{}", user.id, MASTER_APP_ID.to_owned()));
                let result = hasher.finalize();
                let id = String::from_utf8_lossy(&result[..]).to_string();
                let aa = ApprovedApplication {
                    id,
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
                            .map_err(ApiResponse::InternalServerErrorWithMessage)
                            .unwrap();
                        let signed_ref_token = encode(&Header::default(), &r, &KEYS.encoding)
                            .map_err(|_| ApiResponse::InternalServerError)
                            .unwrap();
                        let signed_auth_token = encode(&Header::default(), &a, &KEYS.encoding)
                            .map_err(|_| ApiResponse::InternalServerError)
                            .unwrap();

                        ApiResponse::Success(
                            serde_json::to_value(AuthResponse {
                                auth_token: signed_auth_token,
                                refresh_token: signed_ref_token,
                            })
                            .unwrap(),
                        )
                    }
                    Err(_) => ApiResponse::InternalServerErrorWithMessage(anyhow!(
                        "Could not generate access, please contact support with user_id: {}",
                        user.id
                    )),
                }
            } else {
                ApiResponse::InternalServerError
            }
        }
    } else {
        ApiResponse::NotFound
    }
}

async fn revoke_discord(
    Extension(mut current_user): Extension<User>,
    Extension(scopes): Extension<Scopes>,
) -> ApiResponse {
    if !Scope::check_scopes(&scopes, &Scope::SetDiscordID) {
        return ApiResponse::Unauthorized;
    }
    if let Some(_sf) = current_user.discord_sf {
        if current_user.email.is_some() && current_user.hashed_password.is_some() {
            current_user.discord_sf = None;
            db_handler::put_item::<User>(current_user)
                .await
                .map_err(ApiResponse::InternalServerErrorWithMessage)
                .unwrap();
            ApiResponse::Success(json!("Success"))
        } else {
            ApiResponse::MissingData(json!("User requires email/password login enabled."))
        }
    } else {
        ApiResponse::NotFound
    }
}

async fn get_new_token(extract::Json(token): extract::Json<RefreshTokenRequest>) -> ApiResponse {
    if let Ok(token) = RefreshToken::from_header_str(&token.refresh_token).await {
        match db_handler::get_item_from_table_with_filter_by_id::<RefreshTokenDB>(&token.hash())
            .await
        {
            Ok(Some(t)) => {
                let mut token = token;
                if t.valid && token.app_id == t.app_id {
                    let (r, a) =
                        generate_token_pair(token.user_id, t.app_id, Some(token.family), t.scopes)
                            .await
                            .map_err(|_| ApiResponse::InternalServerError)
                            .unwrap();
                    token
                        .invalidate()
                        .await
                        .map_err(ApiResponse::InternalServerErrorWithMessage)
                        .unwrap();

                    let signed_ref_token = encode(&Header::default(), &r, &KEYS.encoding)
                        .map_err(|_| ApiResponse::InternalServerError)
                        .unwrap();
                    let signed_auth_token = encode(&Header::default(), &a, &KEYS.encoding)
                        .map_err(|_| ApiResponse::InternalServerError)
                        .unwrap();

                    ApiResponse::Success(
                        serde_json::to_value(AuthResponse {
                            auth_token: signed_auth_token,
                            refresh_token: signed_ref_token,
                        })
                        .unwrap(),
                    )
                } else {
                    // Might be a rewind attack, invalidate family
                    RefreshToken::invalidate_all_for_family(token.family)
                        .await
                        .map_err(ApiResponse::InternalServerErrorWithMessage)
                        .unwrap();
                    ApiResponse::Unauthorized
                }
            }
            Ok(None) => ApiResponse::Unauthorized,
            Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
        }
    } else {
        ApiResponse::Unauthorized
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
