mod config;
mod db;
mod error;
mod handlers;
mod models;
mod services;

use axum::{
    routing::{get, post, put, delete},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use std::net::SocketAddr;

use config::Config;
use handlers::{auth, sessions};
use services::JwtService;
use db::DbPool;

// Unified app state
#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub config: Config,
    pub jwt: JwtService,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qlock_api=debug,tower_http=debug".into()),
        )
        .init();

    // Load config
    let config = Config::from_env();
    let port = config.port;

    // Connect to database
    let db = db::connect(&config).await;

    // Initialize services
    let jwt = JwtService::new(&config);

    // Create unified app state
    let state = AppState {
        db,
        config: config.clone(),
        jwt,
    };

    // CORS configuration - allow all configured origins
    let origins: Vec<axum::http::HeaderValue> = config.allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();
    
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::COOKIE,
        ])
        .allow_credentials(true);

    // Build router
    let app = Router::new()
        // Health check for deployment platforms
        .route("/", get(|| async { "OK" }))
        .route("/health", get(|| async { "OK" }))
        // Auth routes
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/google", get(auth::google_auth))
        .route("/api/auth/google/callback", get(auth::google_callback))
        .route("/api/auth/github", get(auth::github_auth))
        .route("/api/auth/github/callback", get(auth::github_callback))
        // Session routes
        .route("/api/sessions", get(sessions::list_sessions))
        .route("/api/sessions", post(sessions::create_session))
        .route("/api/sessions/sync", post(sessions::sync_sessions))
        .route("/api/sessions/:id", put(sessions::update_session))
        .route("/api/sessions/:id", delete(sessions::delete_session))
        // Single state for all routes
        .with_state(state)
        // Middleware
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("🚀 Qlock API server running on http://localhost:{}", port);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
