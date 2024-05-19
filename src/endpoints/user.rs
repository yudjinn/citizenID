use anyhow::anyhow;
use axum::{
    extract::Query,
    middleware,
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    db_handler,
    model::{
        ApprovedApplication, CreateUserEmail, RSILinkUser, RefreshToken, Scope, Scopes, UpdateUser,
        User, UserStatus,
    },
    utils::{hash_password, ApiResponse},
    MASTER_APP_ID,
};

use super::login::auth_middleware;

pub fn get_router() -> Router {
    Router::new()
        .route("/", get(get_user))
        .route("/", patch(update_user))
        .route("/", delete(delete_user))
        .route("/apps", get(get_approved_applications))
        .route("/link", get(begin_rsi_link))
        .route("/link", post(link_rsi_account))
        .layer(middleware::from_fn(auth_middleware))
        .route("/", post(create_user_from_email))
}

async fn get_user(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
) -> ApiResponse {
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

                    ApiResponse::Success(serde_json::to_value(user_resp).unwrap())
                } else {
                    ApiResponse::Unauthorized
                }
            }
            Ok(None) => ApiResponse::NotFound,
            Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
        }
    } else {
        ApiResponse::Unauthorized
    }
}

async fn delete_user(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
) -> ApiResponse {
    if Scope::check_scopes(&_scopes, &crate::model::Scope::SetUser) {
        let mut user = current_user.clone();
        user.status = UserStatus::Inactive;
        match db_handler::update_item::<User>(current_user.id.to_string(), user).await {
            Ok(_) => match RefreshToken::invalidate_all_for_user(current_user.id).await {
                Ok(_) => ApiResponse::Success(json!("Success.")),
                Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
            },
            Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
        }
    } else {
        ApiResponse::Unauthorized
    }
}

async fn get_approved_applications(Extension(current_user): Extension<User>) -> ApiResponse {
    match db_handler::get_all_from_table_with_filter_by_index::<ApprovedApplication>(
        "user_id",
        &current_user.id.to_string(),
    )
    .await
    {
        Ok(apps) => ApiResponse::Success(serde_json::to_value(apps).unwrap()),
        Err(_) => ApiResponse::NotFound,
    }
}

async fn create_user_from_email(user: Json<CreateUserEmail>) -> ApiResponse {
    // check the item doesnt already exist
    match db_handler::get_item_from_table_with_filter_by_index::<User>("email", &user.email).await {
        Ok(Some(_)) => ApiResponse::ResourceExists,
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
                            Ok(_) => ApiResponse::Success(serde_json::to_value(u).unwrap()),
                            Err(_) => ApiResponse::InternalServerErrorWithMessage(anyhow!("Could not generate access, please contact support with user_id: {}", u.id))
                        }
                    }
                    Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
                },
                Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
            }
        }
        Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
    }
}

async fn update_user(
    Extension(current_user): Extension<User>,
    Extension(_scopes): Extension<Scopes>,
    update: Json<UpdateUser>,
) -> ApiResponse {
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
                        Err(e) => return ApiResponse::InternalServerErrorWithMessage(e),
                    }
                }
                if invalidate {
                    RefreshToken::invalidate_all_for_user(current_user.id)
                        .await
                        .map_err(ApiResponse::InternalServerErrorWithMessage)
                        .unwrap();
                }
                match db_handler::update_item::<User>(current_user.id.to_string(), obj).await {
                    Ok(u) => ApiResponse::Success(serde_json::to_value(u).unwrap()),
                    Err(e) => ApiResponse::InternalServerErrorWithMessage(e),
                }
            }
            Ok(None) => ApiResponse::NotFound,
            Err(_) => ApiResponse::InternalServerError,
        }
    } else {
        ApiResponse::Unauthorized
    }
}

async fn begin_rsi_link(
    Extension(current_user): Extension<User>,
    Extension(scopes): Extension<Scopes>,
) -> ApiResponse {
    if Scope::check_scopes(&scopes, &Scope::SetRSIID) {
        let ret: RSILinkUser = current_user.into();
        ApiResponse::Success(serde_json::to_value(ret).unwrap())
    } else {
        ApiResponse::Unauthorized
    }
}

#[allow(dead_code, non_snake_case)]
#[derive(Serialize, Debug)]
struct Vars {
    CreatorQuery: CreatorQuery,
}

#[allow(dead_code)]
#[derive(Serialize, Debug)]
struct CreatorQuery {
    nickname: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Data {
    creator: Creator,
}

#[allow(dead_code, non_snake_case)]
#[derive(Deserialize, Debug)]
struct Creator {
    bio: Option<String>,
    displayName: String,
    nickname: String,
}

#[derive(Deserialize)]
struct RsiQs {
    account_name: String,
}

async fn link_rsi_account(
    Query(query): Query<RsiQs>,
    Extension(current_user): Extension<User>,
    Extension(scopes): Extension<Scopes>,
) -> ApiResponse {
    let rsi_account_name = query.account_name;
    if !Scope::check_scopes(&scopes, &Scope::SetRSIID) {
        return ApiResponse::Unauthorized;
    }

    if rsi_account_name.is_empty() {
        return ApiResponse::MissingData(json!("Account name not specified."));
    }

    if !db_handler::get_all_from_table_with_filter_by_index::<User>("rsi_id", &rsi_account_name)
        .await
        .unwrap()
        .is_empty()
    {
        return ApiResponse::ResourceExists;
    };

    let endpoint = "https://robertsspaceindustries.com/community-hub/api/v1/graphql";
    let query = r#"query getAccount($CreatorQuery: CreatorQuery!)
         {
          creator(query: $CreatorQuery) {
            ... Account
              }
         }
        fragment Account on Account {
          bio
          displayName
          nickname
        }
    "#;
    let client = reqwest_graphql::Client::new(endpoint);
    let vars = Vars {
        CreatorQuery: CreatorQuery {
            nickname: rsi_account_name,
        },
    };
    match client.query_with_vars::<Data, Vars>(query, vars).await {
        Ok(data) => {
            // check the thing matches
            if data
                .creator
                .bio
                .is_some_and(|b| b.contains(&current_user.sentinel))
            {
                let mut update = current_user.clone();
                update.rsi_id = Some(data.creator.displayName);
                update.status = UserStatus::Active;
                db_handler::put_item::<User>(update)
                    .await
                    .map_err(ApiResponse::InternalServerErrorWithMessage)
                    .unwrap();
                ApiResponse::Success(json!("Success"))
            } else {
                ApiResponse::MissingData(json!("Sentinel value not found in bio."))
            }
        }
        Err(e) => ApiResponse::InternalServerErrorWithMessage(anyhow::Error::msg(e)),
    }
}
