use axum::extract;
use axum::routing::post;
use axum::{middleware, response::IntoResponse, routing::get, Extension, Json, Router};

use crate::db_handler;
use crate::model::{Application, ApplicationResponse, CreateApplication, User};
use crate::utils::ApiResponse;

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(get_apps))
        .route("/new", post(create_app))
        .route("/delete/:app_id", post(delete_app))
        .layer(middleware::from_fn(auth_middleware))
}

async fn get_apps(
    Extension(current_user): Extension<User>,
) -> Result<Json<Vec<ApplicationResponse>>, impl IntoResponse> {
    match db_handler::get_all_from_table_with_filter_by_index::<Application>(
        "user_id",
        &current_user.id.to_string(),
    )
    .await
    {
        Ok(user) => Ok(Json(
            user.clone().iter().map(|a| a.to_owned().into()).collect(),
        )),
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
    }
}

async fn create_app(
    Extension(current_user): Extension<User>,
    extract::Json(app): extract::Json<CreateApplication>,
) -> Result<Json<Application>, impl IntoResponse> {
    let new = Application::new_from_template(&app, current_user.id).await;
    match db_handler::put_item::<Application>(new).await {
        Ok(u) => Ok(Json(u)),
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
    }
}
async fn delete_app(
    Extension(current_user): Extension<User>,
    app_id: String,
) -> Result<(), impl IntoResponse> {
    match db_handler::get_item_from_table_with_filter_by_id::<Application>(&app_id).await {
        Ok(Some(app)) => {
            if current_user.id != app.user_id {
                return Err(ApiResponse::Unauthorized);
            }
            match db_handler::delete_item::<Application>(app.id).await {
                Ok(_) => Ok(()),
                Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
            }
        }
        Ok(None) => Err(ApiResponse::NotFound),
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
    }
}
