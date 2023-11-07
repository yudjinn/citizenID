use poem_openapi::Tags;

pub mod login;
pub mod user;

#[derive(Tags)]
pub enum ApiTags {
    User,
    Application,
}
