use axum::extract::{self, Path};
use axum::routing::{delete, patch, post};
use axum::{middleware, routing::get, Extension, Router};
use serde_json::json;
use uuid::Uuid;

use crate::db_handler;
use crate::model::{
    Application, ApplicationDB, ApplicationResponse, CreateApplication, Scope, Scopes,
    UpdateApplication, User,
};
use crate::utils::ApiResponse;

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(get_apps))
        .route("/", post(create_app))
        .route("/:app_id", get(get_app))
        .route("/:app_id", delete(delete_app))
        .route("/:app_id", patch(update_callbacks))
        .layer(middleware::from_fn(auth_middleware))
}

async fn get_apps(Extension(current_user): Extension<User>) -> ApiResponse {
    match db_handler::get_all_from_table_with_filter_by_index::<ApplicationDB>(
        "user_id",
        &current_user.id.to_string(),
    )
    .await
    {
        Ok(apps) => ApiResponse::Success(
            serde_json::to_value(
                apps.clone()
                    .iter()
                    .map(|a| a.to_owned().into())
                    .collect::<Vec<ApplicationResponse>>(),
            )
            .unwrap(),
        ),
        Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
    }
}

async fn get_app(Extension(current_user): Extension<User>, Path(id): Path<Uuid>) -> ApiResponse {
    match db_handler::get_item_from_table_with_filter_by_id::<ApplicationDB>(&id.to_string()).await
    {
        Ok(Some(app)) => {
            if app.user_id == current_user.id {
                return ApiResponse::Success(serde_json::to_value(app).unwrap());
            }
            ApiResponse::Unauthorized
        }
        Ok(None) => ApiResponse::NotFound,
        Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
    }
}

async fn create_app(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
    extract::Json(app): extract::Json<CreateApplication>,
) -> ApiResponse {
    if !Scope::check_scopes(&_scopes, &Scope::Full) {
        return ApiResponse::Unauthorized;
    }
    match Application::new_from_template(&app, current_user.id).await {
        Ok(new) => match db_handler::put_item::<ApplicationDB>(new.into()).await {
            Ok(u) => ApiResponse::Success(serde_json::to_value(u).unwrap()),
            Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
        },
        Err(e) => ApiResponse::MissingData(json!(e.to_string())),
    }
}

//TODO: regen secret for app

async fn update_callbacks(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
    Path(id): Path<Uuid>,
    extract::Json(update): extract::Json<UpdateApplication>,
) -> ApiResponse {
    if !Scope::check_scopes(&_scopes, &Scope::Full) {
        return ApiResponse::Unauthorized;
    }
    if let Ok(Some(mut app)) =
        db_handler::get_item_from_table_with_filter_by_id::<ApplicationDB>(&id.to_string())
            .await
            .map_err(|_| ApiResponse::NotFound)
    {
        if app.user_id != current_user.id {
            return ApiResponse::Unauthorized;
        }
        if update.callback_uris.is_some() {
            for uri in update.callback_uris.as_ref().unwrap() {
                if uri.parse::<http::Uri>().is_err() {
                    return ApiResponse::MissingData(json!(format!(
                        "Uri \"{}\" is malformed.",
                        &uri
                    )));
                }
            }
            app.callback_uris = update.callback_uris.unwrap();
        }
        if update.status.is_some() {
            app.status = update.status.unwrap();
        }
        if update.name.is_some() {
            app.name = update.name.unwrap();
        }
        match db_handler::put_item::<ApplicationDB>(app).await {
            Ok(u) => ApiResponse::Success(serde_json::to_value(u).unwrap()),
            Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
        }
    } else {
        ApiResponse::NotFound
    }
}

async fn delete_app(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
    Path(app_id): Path<String>,
) -> ApiResponse {
    if !Scope::check_scopes(&_scopes, &Scope::Full) {
        return ApiResponse::Unauthorized;
    }
    match db_handler::get_item_from_table_with_filter_by_id::<ApplicationDB>(&app_id).await {
        Ok(Some(app)) => {
            if current_user.id != app.user_id {
                return ApiResponse::Unauthorized;
            }
            match db_handler::delete_item::<ApplicationDB>(app.id.to_string()).await {
                Ok(_) => ApiResponse::Success(json!("Success.")),
                Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
            }
        }
        Ok(None) => ApiResponse::NotFound,
        Err(e) => {
            ApiResponse::InternalServerErrorWithMessage(anyhow::anyhow!("Could not fetch: {}", e))
        }
    }
}
