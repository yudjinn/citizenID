use color_eyre::Result;
use endpoints::login::LoginApi;
use endpoints::{login::oauth_token_url_proxy_discord, user::UserApi};
use hmac::{Hmac, Mac};
use poem::{listener::TcpListener, Server};
use poem::{EndpointExt, Route};
use poem_openapi::{payload::PlainText, OpenApi, OpenApiService};

pub mod db;
pub use db::db as db_handler;
use sha2::Sha256;
pub mod endpoints;
pub mod error;
pub mod model;
pub mod utils;

struct Api;

pub const SERVER_KEY: &[u8] = b"123456";

#[OpenApi]
impl Api {
    #[oai(path = "/ping", method = "get")]
    async fn ping(&self) -> PlainText<String> {
        PlainText("pong!".into())
    }
}

#[cfg(not(feature = "lambda"))]
type RuntimeError = std::io::Error;

#[cfg(feature = "lambda")]
type RuntimeError = poem_lambda::Error;

#[tokio::main]
async fn main() -> Result<(), RuntimeError> {
    db_handler::get_or_init().await;
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }

    tracing_subscriber::fmt::init();

    let api_service = OpenApiService::new((Api, UserApi, LoginApi), "CitizenID", "1.0")
        .server("http://localhost:3000/api");
    let ui = api_service.swagger_ui();

    let server_key = Hmac::<Sha256>::new_from_slice(SERVER_KEY).expect("valid server key");

    let app = Route::new()
        .nest("/api", api_service)
        .at("/discord", oauth_token_url_proxy_discord)
        .nest("/", ui)
        .data(server_key);

    #[cfg(not(feature = "lambda"))]
    let server = Server::new(TcpListener::bind("127.0.0.1:3000")).run(app);

    #[cfg(feature = "lambda")]
    let server = poem_lambda::run(app);

    server.await
}
