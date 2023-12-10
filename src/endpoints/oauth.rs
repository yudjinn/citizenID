use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Request},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Extension, Router,
};
use jsonwebtoken::{encode, Header};
use uuid::Uuid;

use crate::{
    model::{Application, ApplicationRequest, OAuthUser, User, UserStatus},
    utils::ApiResponse,
    KEYS,
};

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(reroute))
        .layer(middleware::from_fn(auth_middleware))
        .layer(middleware::from_fn(oauth_middleware))
}

async fn reroute(
    Extension(application): Extension<Application>,
    Extension(app_request): Extension<ApplicationRequest>,
    Extension(current_user): Extension<User>,
) -> Result<Redirect, impl IntoResponse> {
    // TODO: make this prompt the user for consent

    // If inactive, boot
    if current_user.status != UserStatus::Active {
        return Err(ApiResponse::Unauthorized);
    }
    let mut resp_headers = HeaderMap::new();
    let location = if app_request.request_for.is_some()
        && !app_request.request_for.clone().unwrap().is_empty()
    {
        app_request.request_for.unwrap()
    } else {
        let t = application.callback_uris.get(0).unwrap().to_owned();
        t
    };

    if location.is_empty() {
        return Err(ApiResponse::NotFound);
    }
    resp_headers.insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
    // TODO: make a jwt auth token  with user info
    // resp_headers.insert("corvus_key", )
    let auth_payload = OAuthUser {
        id: current_user.id,
        rsi_id: current_user.rsi_id.unwrap(),
    };
    let signed_payload = encode(&Header::default(), &auth_payload, &KEYS.encoding)
        .map_err(|_| ApiResponse::InternalServerError)?;
    resp_headers.insert(
        "corvus-key",
        HeaderValue::from_str(&signed_payload).unwrap(),
    );

    Ok(Redirect::to(&location))
}

pub async fn oauth_middleware(
    mut req: Request<Body>,
    next: Next<Body>,
) -> Result<Response, impl IntoResponse> {
    let corvus_key = if let Some(corvus_key) = get_header("corvus_key", &req) {
        corvus_key
    } else {
        return Err(ApiResponse::Unauthorized);
    };

    let corvus_secret = if let Some(corvus_secret) = get_header("corvus_secret", &req) {
        corvus_secret
    } else {
        return Err(ApiResponse::Unauthorized);
    };

    let corvus_request = if let Some(corvus_request) = get_header("corvus_request", &req) {
        Some(corvus_request)
    } else {
        None
    };

    let id = Uuid::parse_str(&corvus_key).map_err(|_| ApiResponse::InternalServerError)?;
    let app_request = ApplicationRequest {
        id,
        secret: corvus_secret.to_owned(),
        request_for: corvus_request,
    };

    let app = Application::from_request(app_request.clone())
        .await
        .map_err(ApiResponse::InternalServerErrorWithMessage)?;

    req.extensions_mut().insert(app);
    req.extensions_mut().insert(app_request);
    Ok(next.run(req).await)
}

fn get_header(key: &str, req: &Request<Body>) -> Option<String> {
    let ret = req.headers().get(key).and_then(|h| h.to_str().ok());

    if let Some(corvus_key) = ret {
        return Some(corvus_key.to_owned());
    } else {
        return None;
    };
}
