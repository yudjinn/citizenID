use anyhow::anyhow;
use axum::{
    extract::{Path, Query},
    middleware::{self},
    response::Response,
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::CookieJar;

use jsonwebtoken::{decode, DecodingKey, Validation};
use uuid::Uuid;

use crate::{
    db_handler,
    model::{Application, ApprovedApplication, AuthReview, OAuthUser, RefreshToken, Scope, User},
    utils::{generate_token_pair, ApiResponse},
};

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(init_authorization))
        .route("/authorize", post(approve_authorization))
        .layer(middleware::from_fn(auth_middleware))
        .route("/test", get(test_token))
}

// Flow should be:
// get code -> prompt user for response -> hit reroute with code -> redirect to uri with values in body
// async fn get_code

async fn test_token(
    Path(application_id): Path<Uuid>,
    jar: CookieJar,
) -> Result<String, ApiResponse> {
    let auth = jar.get("corvus_auth").unwrap().value().to_owned();
    let application = db_handler::get_item_from_table_with_filter_by_id::<Application>(
        &application_id.to_string(),
    )
    .await
    .unwrap()
    .unwrap();
    match decode::<OAuthUser>(
        &auth,
        &DecodingKey::from_secret(application.secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(d) => Ok(format!("{:?}", d.claims)),
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(
            anyhow::Error::msg(e.to_string()),
        )),
    }
}

// TODO: application get-auth-token
// Params: application id, `corvus-auth` key
// Returns: Authkey tied to user (using scopes)

pub async fn init_authorization(
    app_id: Query<Uuid>,
    redirect_uri: Option<Query<String>>,
    state: Query<String>,
    scopes: Query<String>,
    Extension(current_user): Extension<User>,
) -> Result<Json<AuthReview>, ApiResponse> {
    // flow:
    // hit `authorize` with appid, etc, returns a token and a view of the app/scopes you're allowing
    // hit the continue endpoint with token acts as "acceptance" returns a redirect to the redirect_uri with the token and state
    // this registers the token to the user with the provided scopes. Maybe I add a token app source as an option uuid?
    // the app then has the ability to make requests using that token and can follow the normal auth flow with exchanging it for an auth token
    if let Some(app) =
        db_handler::get_item_from_table_with_filter_by_id::<Application>(&app_id.to_string())
            .await
            .unwrap()
    {
        if redirect_uri.is_some() {
            //TODO: decode this if needed
            let parsed = redirect_uri.unwrap().to_string();
            let ri = if app.callback_uris.contains(&parsed) {
                parsed
            } else {
                app.callback_uris.first().unwrap().clone()
            };
            let s: Vec<Scope> = scopes.split('+').map(|t| t.to_owned().into()).collect();
            let st = state.to_string();
            // Return jwt of the userid, app_id, callback, state, and scopes as a "code"
            let review = AuthReview {
                app_id: app.id,
                app_name: app.name,
                user_id: current_user.id,
                redirect_uri: ri,
                scopes: s,
                state: st,
            };
            Ok(Json(review))
        } else {
            Err(ApiResponse::MissingData)
        }
    } else {
        Err(ApiResponse::NotFound)
    }
}

pub async fn approve_authorization(
    Extension(current_user): Extension<User>,
    Json(auth): Json<AuthReview>,
) -> Result<Json<RefreshToken>, ApiResponse> {
    //
    let aa = ApprovedApplication {
        id: Uuid::new_v4(),
        user_id: current_user.id,
        scopes: auth.scopes,
        app_id: auth.app_id,
        app_name: auth.app_name,
    };
    match db_handler::put_item::<ApprovedApplication>(aa).await {
        Ok(auth) => {
            let (r, _) = generate_token_pair(current_user.id, auth.app_id, None, auth.scopes)
                .await
                .unwrap();
            Ok(Json(r))
        }
        Err(_) => Err(ApiResponse::InternalServerErrorWithMessage(anyhow!(
            "Could not associate user with application."
        ))),
    }
}
