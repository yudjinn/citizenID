use anyhow::anyhow;

use axum::{
    extract::Query,
    middleware::{self},
    routing::{get, post},
    Extension, Json, Router,
};

use base64ct::{Base64, Encoding};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    db_handler,
    model::{
        ApplicationDB, ApprovedApplication, AuthReview, AuthSuccess, OauthParams, Scope, User,
    },
    utils::{generate_token_pair, ApiResponse},
};

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(init_authorization))
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
    let id = Base64::encode_string(&result);
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

pub async fn init_authorization(
    params: Option<Query<OauthParams>>,
    Extension(current_user): Extension<User>,
) -> ApiResponse {
    let params = if params.is_none() {
        return ApiResponse::MissingData(json!("Missing query parameters."));
    } else {
        params.unwrap()
    };
    if let Ok(Some(app)) = db_handler::get_item_from_table_with_filter_by_id::<ApplicationDB>(
        &params.app_id.to_string(),
    )
    .await
    {
        let ri = match params.redirect_uri.as_ref() {
            Some(parsed) => {
                if app.callback_uris.contains(&parsed) {
                    parsed.clone()
                } else {
                    return ApiResponse::MissingData(json!("Invalid URI."));
                }
            }
            None => app.callback_uris.first().unwrap().clone(),
        };

        let mut sc = vec![];
        for s in params.scopes.split('+').map(|t| t.to_owned()) {
            let b: Scope = s.clone().into();
            if b == Scope::Invalid {
                return ApiResponse::MissingData(json!(format!("Scope {} is invalid", s)));
            } else {
                sc.push(b);
            }
        }
        let st = params.state.to_string();
        let review = AuthReview {
            app_id: app.id,
            app_name: app.name,
            user_id: current_user.id,
            redirect_uri: ri,
            scopes: sc,
            state: st,
        };
        return ApiResponse::Success(serde_json::to_value(review).unwrap());
    } else {
        return ApiResponse::MissingData(json!("Unknown Application."));
    }
}

pub async fn approve_authorization(
    Extension(current_user): Extension<User>,
    Json(auth): Json<AuthReview>,
) -> ApiResponse {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", auth.user_id, auth.app_id));
    let result = hasher.finalize();
    let id = Base64::encode_string(&result);
    let aa = ApprovedApplication {
        id,
        user_id: current_user.id,
        scopes: auth.scopes,
        app_id: auth.app_id,
        app_name: auth.app_name,
    };
    match db_handler::put_item::<ApprovedApplication>(aa).await {
        Ok(approved_app) => {
            match db_handler::get_item_from_table_with_filter_by_id::<ApplicationDB>(
                &approved_app.app_id.to_string(),
            )
            .await
            {
                Ok(Some(app)) => {
                    if let Ok(succ) =
                        AuthSuccess::new(current_user.id.to_string(), app.id.to_string()).await
                    {
                        return ApiResponse::Success(json!(succ));
                    } else {
                        return ApiResponse::InternalServerErrorWithMessage(anyhow!(
                            "Could not associate user with application."
                        ));
                    }
                }
                _ => return ApiResponse::InternalServerError,
            }
        }
        Err(_) => ApiResponse::InternalServerErrorWithMessage(anyhow!(
            "Could not associate user with application."
        )),
    }
}
