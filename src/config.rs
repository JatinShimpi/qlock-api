use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub frontend_url: String,          // Primary/default frontend URL
    pub allowed_origins: Vec<String>,   // All allowed frontend origins for CORS
    pub mongodb_uri: String,
    pub database_name: String,
    pub jwt_secret: String,
    pub jwt_expiry_hours: i64,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_url: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_url: String,
    pub rate_limit_per_minute: u64,
    pub rate_limit_burst_size: u32,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        let frontend_url = env::var("FRONTEND_URL")
            .unwrap_or_else(|_| "http://localhost:5173".to_string());

        // Parse comma-separated allowed origins, or use frontend_url as default
        let allowed_origins: Vec<String> = env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| frontend_url.clone())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            port: env::var("PORT")
                .unwrap_or_else(|_| "3001".to_string())
                .parse()
                .expect("PORT must be a number"),
            frontend_url,
            allowed_origins,
            mongodb_uri: env::var("MONGODB_URI")
                .unwrap_or_else(|_| "mongodb://localhost:27017".to_string()),
            database_name: env::var("DATABASE_NAME")
                .unwrap_or_else(|_| "qlock".to_string()),
            jwt_secret: env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            jwt_expiry_hours: env::var("JWT_EXPIRY_HOURS")
                .unwrap_or_else(|_| "168".to_string())
                .parse()
                .expect("JWT_EXPIRY_HOURS must be a number"),
            google_client_id: env::var("GOOGLE_CLIENT_ID")
                .unwrap_or_default(),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET")
                .unwrap_or_default(),
            google_redirect_url: env::var("GOOGLE_REDIRECT_URL")
                .unwrap_or_else(|_| "http://localhost:3001/api/auth/google/callback".to_string()),
            github_client_id: env::var("GITHUB_CLIENT_ID")
                .unwrap_or_default(),
            github_client_secret: env::var("GITHUB_CLIENT_SECRET")
                .unwrap_or_default(),
            github_redirect_url: env::var("GITHUB_REDIRECT_URL")
                .unwrap_or_else(|_| "http://localhost:3001/api/auth/github/callback".to_string()),
            rate_limit_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            rate_limit_burst_size: env::var("RATE_LIMIT_BURST_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
        }
    }

    // Helper to check if an origin is allowed
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == origin)
    }

    // Get redirect URL based on request origin, falling back to default
    pub fn get_redirect_url(&self, origin_header: Option<&str>) -> &str {
        if let Some(origin) = origin_header {
            if self.is_origin_allowed(origin) {
                return self.allowed_origins.iter()
                    .find(|o| o.as_str() == origin)
                    .map(|s| s.as_str())
                    .unwrap_or(&self.frontend_url);
            }
        }
        &self.frontend_url
    }
}
