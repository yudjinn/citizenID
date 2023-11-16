use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use poem::{error::BadRequest, handler, web::Data, Request};
use poem_openapi::{
    auth::ApiKey,
    payload::{Json, PlainText},
    ApiResponse, OpenApi, SecurityScheme,
};
use sha2::Sha256;

use crate::model::AuthLogin;
use crate::model::{LoginUser, User};
use crate::{db_handler, utils::check_password};

/// ApiKey authorization
#[derive(SecurityScheme)]
#[oai(
    ty = "api_key",
    key_name = "X-API-Key",
    key_in = "header",
    checker = "api_checker"
)]
pub struct CorvusApiKeyAuthorization(pub User);
// pub struct CorvusApiKeyAuthorization(pub AuthLogin);

type ServerKey = Hmac<Sha256>;

async fn api_checker(req: &Request, api_key: ApiKey) -> Option<User> {
    let server_key = req.data::<ServerKey>().unwrap();
    VerifyWithKey::<User>::verify_with_key(api_key.key.as_str(), server_key).ok()
}

#[derive(ApiResponse)]
#[allow(dead_code)]
pub enum LoginResponse {
    #[oai(status = 200)]
    LoginSuccess(Json<AuthLogin>),

    #[oai(status = 403)]
    Unauthorized,

    #[oai(status = 422)]
    MissingData,

    #[oai(status = 500)]
    InternalServerErrorWithMessage(PlainText<String>),

    #[oai(status = 500)]
    InternalServerError,

    #[oai(status = 500)]
    NotImplemented,
}

pub struct LoginApi;

#[OpenApi]
impl LoginApi {
    #[oai(path = "/login", method = "post", operation_id = "Login via Email")]
    async fn login_with_email(
        &self,
        server_key: Data<&ServerKey>,
        login: Json<LoginUser>,
    ) -> LoginResponse {
        match login.0 {
            LoginUser {
                email: Some(email),
                password: Some(password),
                ..
            } => {
                match db_handler::get_item_from_table_with_filter_by_index::<User>("email", &email)
                    .await
                {
                    Ok(Some(user)) => {
                        if user.hashed_password.is_none() || user.salt.is_none() {
                            return LoginResponse::Unauthorized;
                        }
                        if let Ok(v) = check_password(
                            &password,
                            &user.salt.clone().unwrap(),
                            &user.hashed_password.clone().unwrap(),
                        )
                        .await
                        {
                            if v {
                                //todo create session/token
                                if let Ok(l) = user.sign_with_key(server_key.0) {
                                    LoginResponse::LoginSuccess(Json(AuthLogin {
                                        access_token: todo!(),
                                        refresh_token: todo!(),
                                    }))
                                } else {
                                    LoginResponse::InternalServerError
                                }
                            } else {
                                LoginResponse::Unauthorized
                            }
                        } else {
                            LoginResponse::InternalServerError
                        }
                    }
                    Ok(None) => LoginResponse::Unauthorized,
                    Err(e) => {
                        LoginResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e)))
                    }
                }
            }
            _ => LoginResponse::MissingData,
        }
    }

    // async fn login_with_discord(&self) -> UserResponse {
    //     LoginUser {
    //         discord_sf: Some(discord_sf),
    //         ..
    //     } => {
    //         match db_handler::get_item_from_table_with_filter_by_index::<User>(
    //             "discord_sf",
    //             &discord_sf,
    //         )
    //         .await
    //         {
    //             Ok(Some(user)) => UserResponse::Ok(Json(user.clone())),
    //             Ok(None) => UserResponse::NotFound,
    //             Err(e) => {
    //                 UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e)))
    //             }
    //         }
    //     }
    //     _ => UserResponse::MissingData,
    // }
    //     todo!()
    // }
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
