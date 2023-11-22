use axum::{routing::get, Router};
use endpoints::login::Keys;
use lazy_static::lazy_static;

pub mod db;
pub use db::db as db_handler;
pub mod endpoints;
pub mod error;
pub mod model;
pub mod utils;

lazy_static! {
    static ref SECRET: String = std::env::var_os("SECRET_KEY")
        .unwrap_or("DEVKEY".into())
        .into_string()
        .unwrap();
    static ref KEYS: endpoints::login::Keys = Keys::new(SECRET.as_bytes());
}

#[cfg(not(feature = "lambda"))]
type RuntimeError = hyper::Error;

#[cfg(feature = "lambda")]
type RuntimeError = lambda_http::Error;

async fn ping() -> String {
    "pong".into()
}

#[tokio::main]
async fn main() -> Result<(), RuntimeError> {
    // db_handler::get_or_init().await;
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/ping", get(ping))
        .nest("/user", endpoints::user::get_router())
        .nest("/applications", endpoints::apps::get_router())
        .nest("/", endpoints::login::get_router());

    #[cfg(not(feature = "lambda"))]
    {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    #[cfg(feature = "lambda")]
    // todo https://github.com/awslabs/aws-lambda-rust-runtime/blob/main/examples/http-axum/src/main.rs
    {
        lambda_http::run(app).await?;
    }
    Ok(())
}
