use anyhow::anyhow;
use axum::{
    middleware,
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use uuid::Uuid;

use crate::{
    db_handler,
    model::{
        ApprovedApplication, CreateUserEmail, RefreshToken, Scope, Scopes, UpdateUser, User,
        UserResponse, UserStatus,
    },
    utils::{hash_password, ApiResponse},
    MASTER_APP_ID,
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
        .route("/", patch(update_user))
        .route("/", delete(delete_user))
        .route("/apps", get(get_approved_applications))
        .layer(middleware::from_fn(auth_middleware))
        .route("/", post(create_user_from_email))
}

async fn get_user(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
) -> Result<Json<UserResponse>, ApiResponse> {
    if Scope::check_scopes(&_scopes, &crate::model::Scope::GetUserFull) {
        // Regular login -> tokin with full scope
        // Oauth -> just id/rsi_id/status?
        match db_handler::get_item_from_table_with_filter_by_id::<User>(
            &current_user.id.to_string(),
        )
        .await
        {
            Ok(Some(user)) => {
                if user.status != UserStatus::Inactive && user.status != UserStatus::Unknown {
                    let user_resp = user.clone();

                    Ok(Json(user_resp.into()))
                } else {
                    Err(ApiResponse::Unauthorized)
                }
            }
            Ok(None) => Err(ApiResponse::NotFound),
            Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
        }
    } else {
        Err(ApiResponse::Unauthorized)
    }
}

async fn delete_user(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
) -> Result<(), ApiResponse> {
    if Scope::check_scopes(&_scopes, &crate::model::Scope::SetUser) {
        let mut user = current_user.clone();
        user.status = UserStatus::Inactive;
        match db_handler::update_item::<User>(current_user.id.to_string(), user).await {
            Ok(_) => match RefreshToken::invalidate_all_for_user(current_user.id).await {
                Ok(_) => Ok(()),
                Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
            },
            Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
        }
    } else {
        Err(ApiResponse::Unauthorized)
    }
}

async fn get_approved_applications(
    Extension(current_user): Extension<User>,
) -> Result<Json<Vec<ApprovedApplication>>, ApiResponse> {
    match db_handler::get_all_from_table_with_filter_by_index::<ApprovedApplication>(
        "user_id",
        &current_user.id.to_string(),
    )
    .await
    {
        Ok(apps) => Ok(Json(apps)),
        Err(_) => Err(ApiResponse::NotFound),
    }
}

async fn create_user_from_email(
    user: Json<CreateUserEmail>,
) -> Result<Json<UserResponse>, ApiResponse> {
    // check the item doesnt already exist
    match db_handler::get_item_from_table_with_filter_by_index::<User>("email", &user.email).await {
        Ok(Some(_)) => Err(ApiResponse::ResourceExists),
        Ok(None) => {
            match User::new_from_email(&user.email, &user.password).await {
                Ok(new) => match db_handler::put_item::<User>(new).await {
                    Ok(u) => {
                        let aa = ApprovedApplication {
                            id: Uuid::new_v4(),
                            user_id: u.id,
                            app_id: MASTER_APP_ID.to_owned(),
                            app_name: "CORVUS".into(),
                            scopes: Scope::all(),
                        };
                        match db_handler::put_item::<ApprovedApplication>(aa).await {
                            Ok(_) => Ok(Json(u.into())),
                            Err(_) => Err(ApiResponse::InternalServerErrorWithMessage(anyhow!("Could not generate access, please contact support with user_id: {}", u.id)))
                        }
                    }
                    Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
                },
                Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
            }
        }
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
    }
}

async fn update_user(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
    update: Json<UpdateUser>,
) -> Result<Json<UserResponse>, ApiResponse> {
    // check the item doesnt already exist
    if Scope::check_scopes(&_scopes, &crate::model::Scope::SetUser) {
        match db_handler::get_item_from_table_with_filter_by_id::<User>(
            &current_user.id.to_string(),
        )
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
                match db_handler::update_item::<User>(current_user.id.to_string(), obj).await {
                    Ok(u) => Ok(Json(u.into())),
                    Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
                }
            }
            Ok(None) => Err(ApiResponse::NotFound),
            Err(_) => Err(ApiResponse::InternalServerError),
        }
    } else {
        Err(ApiResponse::Unauthorized)
    }
}
