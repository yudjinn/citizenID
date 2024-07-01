use anyhow::anyhow;

use axum::{
    extract::Query,
    middleware::{self},
    response::Redirect,
    routing::{get, post},
    Extension, Json, Router,
};

use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    db_handler,
    model::{Application, ApprovedApplication, AuthReview, OauthParams, Scope, User},
    utils::{generate_token_pair, ApiResponse},
};

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(init_authorization))
        .route("/preflight", get(preflight))
        .route("/authorize", post(approve_authorization))
        .layer(middleware::from_fn(auth_middleware))
        .route("/test", get(test_oauth))
}

async fn test_oauth(
    Extension(current_user): Extension<User>,
    Json(auth): Json<AuthReview>,
) -> ApiResponse {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", auth.user_id, auth.app_id));
    let result = hasher.finalize();
    let id = String::from_utf8_lossy(&result[..]).to_string();
    let aa = ApprovedApplication {
        id,
        user_id: current_user.id,
        scopes: auth.scopes,
        app_id: auth.app_id,
        app_name: auth.app_name,
    };
    match db_handler::put_item::<ApprovedApplication>(aa).await {
        Ok(approved_app) => {
            let (r, _) = generate_token_pair(
                current_user.id,
                approved_app.app_id,
                None,
                approved_app.scopes,
            )
            .await
            .unwrap();
            // redirect to endpoint
            ApiResponse::Success(json!(r.id.to_string()))
        }
        Err(_) => ApiResponse::InternalServerErrorWithMessage(anyhow!(
            "Could not associate user with application."
        )),
    }
}

pub async fn preflight(
    params: Query<OauthParams>,
    Extension(_current_user): Extension<User>,
) -> ApiResponse {
    let mut reasons: Vec<String> = vec![];
    if let Some(app) =
        db_handler::get_item_from_table_with_filter_by_id::<Application>(&params.app_id.to_string())
            .await
            .unwrap()
    {
        if params.redirect_uri.is_some()
            && !app
                .callback_uris
                .contains(params.redirect_uri.as_ref().unwrap())
        {
            reasons.push("Invalid redirect URI: Not contained in application spec.".into());
        }
        if params.state.is_empty() {
            reasons.push("Please provide a valid state string.".into());
        }
        for s in params.scopes.split('+').map(|t| t.to_owned()) {
            let b: Scope = s.clone().into();
            if b == Scope::Invalid {
                reasons.push(format!("Scope '{}' is invalid.", s));
            }
        }
    } else {
        reasons.push("App ID Invalid".into());
    }
    if reasons.len() > 0 {
        return ApiResponse::MissingData(json!(reasons));
    }
    return ApiResponse::Success(json!("No issues detected."));
}

pub async fn init_authorization(
    params: Query<OauthParams>,
    Extension(current_user): Extension<User>,
) -> ApiResponse {
    // flow:
    // hit `authorize` with appid, etc, returns a token and a view of the app/scopes you're allowing
    // hit the continue endpoint with token acts as "acceptance" returns a redirect to the redirect_uri with the token and state
    // this registers the token to the user with the provided scopes. Maybe I add a token app source as an option uuid?
    // the app then has the ability to make requests using that token and can follow the normal auth flow with exchanging it for an auth token
    if let Some(app) =
        db_handler::get_item_from_table_with_filter_by_id::<Application>(&params.app_id.to_string())
            .await
            .unwrap()
    {
        let ri = match params.redirect_uri.as_ref() {
            Some(parsed) => {
                if app.callback_uris.contains(&parsed) {
                    parsed.clone()
                } else {
                    app.callback_uris.first().unwrap().clone()
                }
            }
            None => app.callback_uris.first().unwrap().clone(),
        };

        let s: Vec<Scope> = params
            .scopes
            .split('+')
            .map(|t| t.to_owned().into())
            .collect();
        let st = params.state.to_string();
        // Return jwt of the userid, app_id, callback, state, and scopes as a "code"
        let review = AuthReview {
            app_id: app.id,
            app_name: app.name,
            user_id: current_user.id,
            redirect_uri: ri,
            scopes: s,
            state: st,
        };
        ApiResponse::Success(serde_json::to_value(review).unwrap())
    } else {
        ApiResponse::NotFound
    }
}

pub async fn approve_authorization(
    Extension(current_user): Extension<User>,
    Json(auth): Json<AuthReview>,
) -> Result<Redirect, ApiResponse> {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", auth.user_id, auth.app_id));
    let result = hasher.finalize();
    let id = String::from_utf8_lossy(&result[..]).to_string();
    let aa = ApprovedApplication {
        id,
        user_id: current_user.id,
        scopes: auth.scopes,
        app_id: auth.app_id,
        app_name: auth.app_name,
    };
    match db_handler::put_item::<ApprovedApplication>(aa).await {
        Ok(approved_app) => {
            let (r, _) = generate_token_pair(
                current_user.id,
                approved_app.app_id,
                None,
                approved_app.scopes,
            )
            .await
            .unwrap();
            // Encrypt token
            match db_handler::get_item_from_table_with_filter_by_id::<Application>(
                &approved_app.app_id.to_string(),
            )
            .await
            {
                // redirect to endpoint
                Ok(Some(app)) => {
                    let tok = soft_aes::aes::aes_enc_ecb(
                        r.id.as_bytes(),
                        &app.secret.as_bytes()[..32],
                        Some("PKCS7"),
                    )
                    .map_err(|_| ApiResponse::InternalServerError)?;
                    println!("{}", &app.secret);
                    let tok = base64::prelude::BASE64_STANDARD.encode(&tok);
                    let tok = urlencoding::encode(&tok);
                    return Ok(Redirect::temporary(&format!(
                        "{}?token={}",
                        auth.redirect_uri, tok
                    )));
                }
                _ => return Err(ApiResponse::InternalServerError),
            }
        }
        Err(_) => Err(ApiResponse::InternalServerErrorWithMessage(anyhow!(
            "Could not associate user with application."
        ))),
    }
}
