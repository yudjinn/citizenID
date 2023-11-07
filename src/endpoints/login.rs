use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use poem::{error::BadRequest, handler, Request};
use poem_openapi::{auth::ApiKey, SecurityScheme};
use sha2::Sha256;

use crate::model::User;

/// ApiKey authorization
#[derive(SecurityScheme)]
#[oai(
    ty = "api_key",
    key_name = "X-API-Key",
    key_in = "header",
    checker = "api_checker"
)]
struct MyApiKeyAuthorization(User);

type ServerKey = Hmac<Sha256>;

async fn api_checker(req: &Request, api_key: ApiKey) -> Option<User> {
    let server_key = req.data::<ServerKey>().unwrap();
    VerifyWithKey::<User>::verify_with_key(api_key.key.as_str(), server_key).ok()
}

#[handler]
pub async fn oauth_token_url_proxy_discord(
    req: &poem::Request,
    body: poem::Body,
) -> poem::Result<poem::Response> {
    let cli = reqwest::Client::new();
    let body = body.into_vec().await?;
    let resp = cli
        .request(
            req.method().clone(),
            format!(
                "https://discord.com/api/oauth2/token?{}",
                req.uri().query().unwrap_or_default()
            ),
        )
        .header("Content-Type", "application/x-www-form-urlencoded")
        .headers(req.headers().clone())
        .body(body)
        .send()
        .await
        .map_err(BadRequest)?;

    let mut r = poem::Response::default();
    r.set_status(resp.status());
    *r.headers_mut() = resp.headers().clone();
    r.set_body(resp.bytes().await.map_err(BadRequest)?);
    Ok(r)
}
