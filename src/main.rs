use color_eyre::Result;
use endpoints::user::UserApi;
use poem::Route;
use poem::{listener::TcpListener, Server};
use poem_openapi::{payload::PlainText, OpenApi, OpenApiService};

pub mod db;
pub use db::db as db_handler;
pub mod endpoints;
pub mod error;
pub mod model;
pub mod utils;

struct Api;

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
    db_handler::init_db().await.unwrap();
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }

    tracing_subscriber::fmt::init();

    let api_service =
        OpenApiService::new((Api, UserApi), "CitizenID", "1.0").server("http://localhost:3000/api");
    let ui = api_service.swagger_ui();

    let app = Route::new().nest("/api", api_service).nest("/", ui);

    #[cfg(not(feature = "lambda"))]
    let server = Server::new(TcpListener::bind("127.0.0.1:3000")).run(app);

    #[cfg(feature = "lambda")]
    let server = poem_lambda::run(app);

    server.await
}
