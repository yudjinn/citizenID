use poem::web::Path;
use poem_openapi::{
    payload::{Json, PlainText},
    ApiResponse, OpenApi,
};
use uuid::Uuid;

use crate::{
    db_handler,
    endpoints::ApiTags,
    model::{CreateUserEmail, UpdateUser, User},
};

pub struct UserApi;

#[derive(ApiResponse)]
enum UserResponse {
    #[oai(status = 200)]
    OkMulti(Json<Vec<User>>),

    #[oai(status = 200)]
    Ok(Json<User>),

    #[oai(status = 201)]
    UserCreated(Json<User>),

    #[oai(status = 204)]
    UserUpdated(Json<User>),

    #[oai(status = 404)]
    NotFound,

    #[oai(status = 409)]
    UserExists,

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
            Err(_) => UserResponse::InternalServerError,
        }
    }

    #[oai(path = "/", method = "post")]
    async fn create_user_from_email(&self, user: Json<CreateUserEmail>) -> UserResponse {
        // check the item doesnt already exist
        match db_handler::get_item_from_table_with_filter::<User>("email", &user.email).await {
            Ok(Some(_)) => UserResponse::UserExists,
            Ok(None) => {
                let new = User::new_from_email(&user.email, &user.password).await;
                match db_handler::put_item::<User>(new).await {
                    Ok(u) => UserResponse::UserCreated(Json(u)),
                    Err(e) => {
                        UserResponse::InternalServerErrorWithMessage(PlainText(e.to_string()))
                    }
                }
            }
            Err(e) => UserResponse::InternalServerErrorWithMessage(PlainText(e.to_string())),
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
                    //todo
                    obj.hashed_password = Some(p);
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
