use bson::oid::ObjectId;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::ApiError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // User ID
    pub email: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone)]
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiry_hours: i64,
}

impl JwtService {
    pub fn new(config: &Config) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            expiry_hours: config.jwt_expiry_hours,
        }
    }

    pub fn create_token(&self, user_id: &ObjectId, email: &str) -> Result<String, ApiError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiry_hours);

        let claims = Claims {
            sub: user_id.to_hex(),
            email: email.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| ApiError::InternalError(format!("Failed to create token: {}", e)))
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, ApiError> {
        decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map(|data| data.claims)
            .map_err(|e| ApiError::Unauthorized(format!("Invalid token: {}", e)))
    }
}
