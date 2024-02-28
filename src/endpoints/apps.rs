use axum::extract::{self, Path};
use axum::routing::{delete, post, put};
use axum::{middleware, routing::get, Extension, Json, Router};
use uuid::Uuid;

use crate::db_handler;
use crate::model::{Application, ApplicationResponse, CreateApplication, UpdateApplication, User};
use crate::utils::ApiResponse;

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(get_apps))
        .route("/new", post(create_app))
        .route("/delete/:app_id", delete(delete_app))
        .route("/update/:app_id", put(update_callbacks))
        .layer(middleware::from_fn(auth_middleware))
}

async fn get_apps(
    Extension(current_user): Extension<User>,
) -> Result<Json<Vec<ApplicationResponse>>, ApiResponse> {
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
) -> Result<Json<Application>, ApiResponse> {
    let new = Application::new_from_template(&app, current_user.id).await;
    match db_handler::put_item::<Application>(new).await {
        Ok(u) => Ok(Json(u)),
        Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
    }
}

async fn update_callbacks(
    Extension(current_user): Extension<User>,
    Path(id): Path<Uuid>,
    extract::Json(update): extract::Json<UpdateApplication>,
) -> Result<Json<ApplicationResponse>, ApiResponse> {
    if let Some(mut app) =
        db_handler::get_item_from_table_with_filter_by_id::<Application>(&id.to_string())
            .await
            .map_err(|_| ApiResponse::NotFound)?
    {
        if app.user_id != current_user.id {
            return Err(ApiResponse::Unauthorized);
        }
        if update.callback_uris.is_some() {
            app.callback_uris = update.callback_uris.unwrap();
        }
        if update.status.is_some() {
            app.status = update.status.unwrap();
        }
        if update.name.is_some() {
            app.name = update.name.unwrap();
        }
        match db_handler::put_item::<Application>(app).await {
            Ok(u) => Ok(Json(u.into())),
            Err(e) => Err(ApiResponse::InternalServerErrorWithMessage(e)),
        }
    } else {
        Err(ApiResponse::NotFound)
    }
}

async fn delete_app(
    Extension(current_user): Extension<User>,
    app_id: String,
) -> Result<(), ApiResponse> {
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
