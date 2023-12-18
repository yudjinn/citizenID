use axum::{
    body::Body,
    extract::Path,
    headers::{Cookie, HeaderMapExt},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, Request},
    middleware::{self, Next},
    response::{Redirect, Response},
    routing::get,
    Extension, Router,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::{
    db_handler,
    model::{Application, ApplicationRequest, OAuthUser, User, UserStatus},
    utils::ApiResponse,
};

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(reroute))
        .layer(middleware::from_fn(auth_middleware))
        .layer(middleware::from_fn(oauth_middleware))
        .route("/test", get(test_token))
}

// Flow should be:
// get code -> prompt user for response -> hit reroute with code -> redirect to uri with values in body
// async fn get_code

async fn test_token(
    Path(application_id): Path<Uuid>,
    req: Request<Body>,
) -> Result<String, ApiResponse> {
    let cookie = req.headers().typed_get::<Cookie>().unwrap();
    let auth = cookie.get("corvus_auth").unwrap().to_owned();
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

async fn reroute(
    Extension(application): Extension<Application>,
    Extension(app_request): Extension<ApplicationRequest>,
    Extension(current_user): Extension<User>,
) -> Result<(HeaderMap, Redirect), ApiResponse> {
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
    let auth_payload = OAuthUser {
        id: current_user.id,
        rsi_id: current_user.rsi_id.unwrap(),
    };
    let signed_payload = encode(
        &Header::default(),
        &auth_payload,
        &EncodingKey::from_secret(application.secret.as_bytes()),
    )
    .map_err(|_| ApiResponse::InternalServerError)?;
    resp_headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!("corvus_auth={}", &signed_payload)).unwrap(),
    );
    // TODO: add a body of url-encoded and send to redirect
    Ok((resp_headers, Redirect::temporary(&location)))
}

// TODO: application get-auth-token
// Params: application id, `corvus-auth` key
// Returns: Authkey tied to user (using scopes)

pub async fn oauth_middleware(
    mut req: Request<Body>,
    next: Next<Body>,
) -> Result<Response, ApiResponse> {
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

    let corvus_request = get_header("corvus_request", &req);

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

    ret.map(|corvus_key| corvus_key.to_owned())
}
