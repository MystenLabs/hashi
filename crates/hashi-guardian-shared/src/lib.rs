use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub access_key: String,
    pub secret_key: String,
    pub bucket_name: String,
}
