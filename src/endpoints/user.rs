use poem_openapi::{
    param::Path,
    payload::{Json, PlainText},
    ApiResponse, OpenApi,
};
use uuid::Uuid;

use crate::{
    db_handler,
    endpoints::ApiTags,
    model::{CreateUserEmail, LoginResponse, LoginUser, UpdateUser, User},
    utils::{check_password, hash_password},
};

pub struct UserApi;

#[derive(ApiResponse)]
enum UserResponse {
    #[oai(status = 200)]
    OkMulti(Json<Vec<User>>),

    #[oai(status = 200)]
    Ok(Json<User>),

    #[oai(status = 200)]
    LoginSuccess(Json<LoginResponse>),

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

#[OpenApi(prefix_path = "/user", tag = "ApiTags::User")]
impl UserApi {
    #[oai(path = "/:user_id", method = "get", operation_id = "Get Single")]
    async fn get_user(&self, user_id: Path<Uuid>) -> UserResponse {
        match db_handler::get_item_from_table_with_filter::<User>("id", &user_id.0.to_string())
            .await
        {
            Ok(Some(user)) => UserResponse::Ok(Json(user.clone())),
            Ok(None) => UserResponse::NotFound,
            Err(e) => UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e))),
        }
    }
    #[oai(path = "/login", method = "post", operation_id = "Login")]
    async fn login(&self, login: Json<LoginUser>) -> UserResponse {
        match login.0 {
            LoginUser {
                email: Some(email),
                password: Some(password),
                ..
            } => match db_handler::get_item_from_table_with_filter::<User>("email", &email).await {
                Ok(Some(user)) => {
                    if user.hashed_password.is_none() || user.salt.is_none() {
                        return UserResponse::Unauthorized;
                    }
                    if let Ok(v) = check_password(
                        &password,
                        &user.salt.unwrap(),
                        &user.hashed_password.unwrap(),
                    )
                    .await
                    {
                        //todo create session/token
                        if v {
                            let l = LoginResponse::default();
                            UserResponse::LoginSuccess(Json(l))
                        } else {
                            UserResponse::Unauthorized
                        }
                    } else {
                        UserResponse::InternalServerError
                    }
                }
                Ok(None) => UserResponse::NotFound,
                Err(e) => {
                    UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e)))
                }
            },
            LoginUser {
                discord_sf: Some(discord_sf),
                ..
            } => {
                match db_handler::get_item_from_table_with_filter::<User>("discord_sf", &discord_sf)
                    .await
                {
                    Ok(Some(user)) => UserResponse::Ok(Json(user.clone())),
                    Ok(None) => UserResponse::NotFound,
                    Err(e) => {
                        UserResponse::InternalServerErrorWithMessage(PlainText(format!("{:?}", e)))
                    }
                }
            }
            _ => UserResponse::MissingData,
        }
    }

    #[oai(
        path = "/",
        method = "post",
        operation_id = "Create from Email/Password"
    )]
    async fn create_user_from_email(&self, user: Json<CreateUserEmail>) -> UserResponse {
        // check the item doesnt already exist
        match db_handler::get_item_from_table_with_filter::<User>("email", &user.email).await {
            Ok(Some(_)) => UserResponse::UserExists,
            _ => match User::new_from_email(&user.email, &user.password).await {
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
        }
    }

    #[oai(path = "/:user_id", method = "put")]
    async fn update_user(&self, user_id: Path<Uuid>, user: Json<UpdateUser>) -> UserResponse {
        // check the item doesnt already exist
        match db_handler::get_item_from_table_with_filter::<User>("id", &user_id.0.to_string())
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
                match db_handler::update_item::<User>(user_id.0, obj).await {
                    Ok(u) => UserResponse::UserUpdated(Json(u)),
                    Err(_) => UserResponse::InternalServerError,
                }
            }
            Ok(None) => UserResponse::NotFound,
            Err(_) => UserResponse::InternalServerError,
        }
    }
}
