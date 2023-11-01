use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use color_eyre::{Report, Result};

pub async fn hash_password(password: &str) -> Result<(String, String)> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    if let Ok(hashed) = argon.hash_password(format!("{}{}", password, salt).as_bytes(), &salt) {
        Ok((hashed.to_string(), salt.to_string()))
    } else {
        Err(Report::msg("Failed to hash password."))
    }
}

pub async fn check_password(password: &str, salt: &str, db_pass: &str) -> Result<bool> {
    let argon = Argon2::default();
    if let Ok(salt_str) = SaltString::from_b64(salt) {
        if let Ok(hashed) =
            argon.hash_password(format!("{}{}", password, salt).as_bytes(), &salt_str)
        {
            Ok(hashed.to_string() == db_pass)
        } else {
            Err(Report::msg("Failed to hash password."))
        }
    } else {
        Err(Report::msg("Failed to parse hash."))
    }
}
