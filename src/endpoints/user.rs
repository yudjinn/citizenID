use poem_openapi::{
    payload::{Json, PlainText},
    ApiResponse, OpenApi,
};

use crate::{
    db_handler,
    endpoints::ApiTags,
    model::{CreateUserEmail, UpdateUser, User},
    utils::hash_password,
};

use super::login::CorvusApiKeyAuthorization;

pub struct UserApi;

#[derive(ApiResponse)]
#[allow(dead_code)]
pub enum UserResponse {
    #[oai(status = 200)]
    Ok(Json<User>),

    #[oai(status = 201)]
    UserCreated(Json<User>),

    #[oai(status = 204)]
    UserUpdated(Json<User>),

    #[oai(status = 403)]
    Unauthorized,

    #[oai(status = 404)]
    NotFound,

    #[oai(status = 409)]
    UserExists,

    #[oai(status = 422)]
    MissingData,

    #[oai(status = 500)]
    InternalServerErrorWithMessage(PlainText<String>),

    #[oai(status = 500)]
    InternalServerError,

    #[oai(status = 500)]
    NotImplemented,
}

// #[derive(OAuthScopes)]
// enum DiscordScopes {
//     // todo
//     #[oai(rename = "public_repo")]
//     PublicRepo,
// }

/// Discord authorization
///
/// - client_id: `1170109958549934211`
/// - client_secret: `Z1VMHGGNqCj2Z9JuWxOxiww62ifOXAae`
// #[derive(SecurityScheme)]
// #[oai(
//     ty = "oauth2",
//     flows(authorization_code(
//         authorization_url = "https://discord.com/oauth2/authorize",
//         token_url = "http://localhost:3000/discord",
//     ))
// )]
// struct DiscordAuthorization(Bearer);

#[OpenApi(prefix_path = "/user", tag = "ApiTags::User")]
impl UserApi {
    #[oai(path = "/:user_id", method = "get", operation_id = "Get Single")]
    async fn get_user(&self, auth: CorvusApiKeyAuthorization) -> UserResponse {
        match db_handler::get_item_from_table_with_filter_by_id::<User>(&auth.0.id.to_string())
            .await
        {
            Ok(Some(user)) => UserResponse::Ok(Json(user.clone())),
            Ok(None) => UserResponse::NotFound,
            Err(e) => UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e))),
        }
    }

    #[oai(
        path = "/",
        method = "post",
        operation_id = "Create from Email/Password"
    )]
    async fn create_user_from_email(&self, user: Json<CreateUserEmail>) -> UserResponse {
        // check the item doesnt already exist
        match db_handler::get_item_from_table_with_filter_by_index::<User>("email", &user.email)
            .await
        {
            Ok(Some(_)) => UserResponse::UserExists,
            Ok(None) => match User::new_from_email(&user.email, &user.password).await {
                Ok(new) => match db_handler::put_item::<User>(new).await {
                    Ok(u) => UserResponse::UserCreated(Json(u)),
                    Err(e) => {
                        UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e)))
                    }
                },
                Err(e) => {
                    UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e)))
                }
            },
            Err(e) => UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e))),
        }
    }

    #[oai(path = "/:user_id", method = "put")]
    async fn update_user(
        &self,
        auth: CorvusApiKeyAuthorization,
        user: Json<UpdateUser>,
    ) -> UserResponse {
        // check the item doesnt already exist
        match db_handler::get_item_from_table_with_filter_by_index::<User>(
            "id",
            &auth.0.id.to_string(),
        )
        .await
        {
            Ok(Some(mut obj)) => {
                if let Some(e) = user.email.clone() {
                    obj.email = Some(e);
                }
                if let Some(p) = user.password.clone() {
                    if let Ok((h, s)) = hash_password(&p).await {
                        obj.hashed_password = Some(h);
                        obj.salt = Some(s);
                    } else {
                        return UserResponse::InternalServerError;
                    }
                }
                match db_handler::update_item::<User>(auth.0.id, obj).await {
                    Ok(u) => UserResponse::UserUpdated(Json(u)),
                    Err(_) => UserResponse::InternalServerError,
                }
            }
            Ok(None) => UserResponse::NotFound,
            Err(_) => UserResponse::InternalServerError,
        }
    }
}
