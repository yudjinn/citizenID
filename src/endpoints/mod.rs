use poem_openapi::Tags;

pub mod user;

#[derive(Tags)]
pub enum ApiTags {
    User,
    Application,
}
