use hashi_guardian_shared::S3Config;

use crate::GuardianResult;
use aws_sdk_s3::Client as S3Client;
use serde::Serialize;

#[derive(Debug)]
pub struct S3Logger {
    pub client: S3Client,
    pub config: S3Config,
}

impl S3Logger {
    pub async fn new(_config: &S3Config) -> GuardianResult<Self> {
        todo!("Implement me")
    }

    /// Create a new S3 Object with a random key
    /// TODO: Implement retries; Introduce ToJson?
    #[cfg(not(test))]
    pub async fn log<T: Serialize>(&self, _value: T) -> GuardianResult<()> {
        todo!("Implement me")
    }

    /// Test S3 connectivity
    pub async fn test_connectivity(&self) -> GuardianResult<()> {
        todo!("Implement me")
    }

    /// Mock logging
    #[cfg(test)]
    pub async fn log<T: Serialize>(&self, _value: T) -> GuardianResult<()> {
        Ok(())
    }

    /// Mock S3Logger
    #[cfg(test)]
    pub async fn mock_for_testing() -> Self {
        let mock_s3_config = S3Config {
            bucket_name: "test-bucket".to_string(),
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
        };
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-east-1"))
            .load()
            .await;
        Self {
            client: S3Client::new(&aws_config),
            config: mock_s3_config,
        }
    }
}
