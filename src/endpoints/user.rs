use axum::{
    middleware,
    response::IntoResponse,
    routing::{get, post, put},
    Extension, Json, Router,
};

use crate::{
    db_handler,
    model::{CreateUserEmail, RefreshToken, UpdateUser, User, UserResponse, UserStatus},
    utils::{hash_password, ApiResponse},
};

use super::login::auth_middleware;

/// Discord authorization
///
/// - client_id: `1170109958549934211`
/// - client_secret: `Z1VMHGGNqCj2Z9JuWxOxiww62ifOXAae`
//  - authorization_url = "https://discord.com/oauth2/authorize"
//  - token_url = "http://localhost:3000/discord"

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(get_user))
        .route("/update", put(update_user))
        .route("/delete", post(delete_user))
        .layer(middleware::from_fn(auth_middleware))
        .route("/new", post(create_user_from_email))
}

async fn get_user(
    Extension(current_user): Extension<User>,
) -> Result<Json<UserResponse>, impl IntoResponse> {
    // TODO make all tokens have a scope, and scope changes what info is returned here
    // Regular login -> tokin with full scope
    // Oauth -> just id/rsi_id/status?
    match db_handler::get_item_from_table_with_filter_by_id::<User>(&current_user.id.to_string())
        .await
    {
        Ok(Some(user)) => Ok(Json(user.clone().into())),
        Ok(None) => Err(ApiResponse::NotFound),
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
    }
}

async fn delete_user(Extension(current_user): Extension<User>) -> Result<(), impl IntoResponse> {
    let mut user = current_user.clone();
    user.status = UserStatus::Inactive;
    match db_handler::update_item::<User>(current_user.id, user).await {
        Ok(_) => Ok(()),
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
    }
}

async fn create_user_from_email(
    user: Json<CreateUserEmail>,
) -> Result<Json<UserResponse>, impl IntoResponse> {
    // check the item doesnt already exist
    match db_handler::get_item_from_table_with_filter_by_index::<User>("email", &user.email).await {
        Ok(Some(_)) => Err(ApiResponse::ResourceExists),
        Ok(None) => match User::new_from_email(&user.email, &user.password).await {
            Ok(new) => match db_handler::put_item::<User>(new).await {
                Ok(u) => Ok(Json(u.into())),
                Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
            },
            Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
        },
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
    }
}

async fn update_user(
    Extension(current_user): Extension<User>,
    update: Json<UpdateUser>,
) -> Result<Json<UserResponse>, impl IntoResponse> {
    // check the item doesnt already exist
    match db_handler::get_item_from_table_with_filter_by_id::<User>(&current_user.id.to_string())
        .await
    {
        Ok(Some(mut obj)) => {
            let mut invalidate = false;
            if let Some(e) = update.email.clone() {
                obj.email = Some(e);
                invalidate = true;
            }
            if let Some(p) = update.password.clone() {
                match hash_password(&p).await {
                    Ok((h, s)) => {
                        obj.hashed_password = Some(h);
                        obj.salt = Some(s);
                        invalidate = true;
                    }
                    Err(e) => return Err(ApiResponse::InternalServerErrorWithMessage(e)),
                }
            }
            if invalidate {
                RefreshToken::invalidate_all_for_user(current_user.id)
                    .await
                    .map_err(ApiResponse::InternalServerErrorWithMessage)?;
            }
            match db_handler::update_item::<User>(current_user.id, obj).await {
                Ok(u) => Ok(Json(u.into())),
                Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
            }
        }
        Ok(None) => Err(ApiResponse::NotFound),
        Err(_) => Err(ApiResponse::InternalServerError),
    }
}
