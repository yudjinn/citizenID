use axum::{
    http::{header::CONTENT_TYPE, HeaderName, HeaderValue, Method},
    routing::get,
    Router,
};
use endpoints::login::Keys;
use lazy_static::lazy_static;

pub mod db;
pub use db::db as db_handler;
use serde_json::json;
use tower_http::cors::CorsLayer;
use utils::ApiResponse;
pub mod endpoints;
pub mod error;
pub mod model;
pub mod utils;

lazy_static! {
    static ref SECRET: String = std::env::var_os("SECRET_KEY")
        .unwrap_or("3)1dxd-#t50&ta-5p(e4(_dw8a(dk#%)k7u4tvf-63_i-a_-ss".into())
        .into_string()
        .unwrap();
    static ref SALT: String = std::env::var_os("SALT_KEY")
        .unwrap_or("p^vzc^j46n#jr6x8".into())
        .into_string()
        .unwrap();
    static ref KEYS: endpoints::login::Keys = Keys::new(SECRET.as_bytes());
    static ref CORS_ORIGINS: Vec<String> = std::env::var_os("CORS_ORIGINS")
        .unwrap_or_default()
        .into_string()
        .unwrap()
        .split(' ')
        .map(|s| s.to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    static ref CORS_ALLOW_CREDENTIALS: bool = std::env::var_os("CORS_ALLOW_CREDENTIALS")
        .unwrap_or("false".into())
        .into_string()
        .unwrap()
        .parse::<bool>()
        .unwrap();
    static ref MASTER_CLIENT_ID: uuid::Uuid = uuid::Uuid::parse_str(
        &std::env::var_os("MASTER_CLIENT_ID")
            .unwrap_or("adaf40f8-0f79-4dd0-a995-912604ccde95".into())
            .into_string()
            .unwrap()
    )
    .unwrap();
}

#[cfg(not(feature = "lambda"))]
type RuntimeError = hyper::Error;

#[cfg(feature = "lambda")]
type RuntimeError = lambda_http::Error;

async fn health() -> ApiResponse {
    ApiResponse::Success(json!("Healthy!"))
}

#[tokio::main]
async fn main() -> Result<(), RuntimeError> {
    // db_handler::get_or_init().await;
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::fmt::init();

    let cors_origins: Vec<HeaderValue> = CORS_ORIGINS
        .clone()
        .iter_mut()
        .map(|v| v.parse::<HeaderValue>().unwrap())
        .collect();

    let mut cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
        ])
        .allow_headers([
            CONTENT_TYPE,
            HeaderName::from_lowercase(b"authorization").unwrap(),
            HeaderName::from_lowercase(b"refresh_token").unwrap(),
        ]);

    cors = cors.allow_credentials(true).allow_origin(cors_origins);

    let app = Router::new()
        .route("/health", get(health))
        .nest("/user", endpoints::user::get_router())
        .nest("/applications", endpoints::apps::get_router())
        .nest("/oauth", endpoints::oauth::get_router())
        .nest("/", endpoints::login::get_router())
        .layer(cors);

    #[cfg(not(feature = "lambda"))]
    {
        let addr = tokio::net::TcpListener::bind("127.0.0.1:3000")
            .await
            .unwrap();
        axum::serve(addr, app).await.unwrap();
    }

    #[cfg(feature = "lambda")]
    // todo https://github.com/awslabs/aws-lambda-rust-runtime/blob/main/examples/http-axum/src/main.rs
    {
        lambda_http::run(app).await.unwrap();
    }
    Ok(())
}
