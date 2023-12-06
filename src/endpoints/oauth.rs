use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Request},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Extension, Router,
};

use crate::{
    model::{Application, ApplicationRequest, User},
    utils::ApiResponse,
};

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(get_apps))
        .layer(middleware::from_fn(auth_middleware))
    // .layer(middleware::from_fn(oauth_middleware))
}

async fn get_apps(
    Extension(application): Extension<Application>,
    Extension(app_request): Extension<ApplicationRequest>,
    Extension(_current_user): Extension<User>,
) -> Result<Redirect, impl IntoResponse> {
    let mut resp_headers = HeaderMap::new();
    let location = if app_request.request_for.is_some() {
        app_request.request_for.unwrap()
    } else {
        application.callback_uris.get(0).unwrap().to_owned()
    };

    if location.is_empty() {
        return Err(ApiResponse::NotFound);
    }
    resp_headers.insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
    Ok(Redirect::temporary(&application.callback_uris[0]))
}

// pub async fn oauth_middleware(
//     mut req: Request<Body>,
//     next: Next<Body>,
// ) -> Result<Response, impl IntoResponse> {
//     let auth_header = req
//         .headers()
//         .get("auth_token")
//         .and_then(|h| h.to_str().ok());

//     // let auth_header = if let Some(auth_header) = auth_header {
//     auth_header
// } else {
// };
// }
