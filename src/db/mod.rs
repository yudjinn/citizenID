pub mod dynamodb;
pub mod tempdb;

#[cfg(feature = "dynamodb")]
pub use dynamodb as db;
#[cfg(feature = "tempdb")]
pub use tempdb as db;

#[cfg(all(feature = "tempdb", feature = "dynamodb"))]
compile_error!("Cannot enable multiple db features");
