use axum::{
    extract::{Query, State},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Redirect},
    Json,
};
use bson::{doc, oid::ObjectId};
use mongodb::Collection;
use serde::{Deserialize, Serialize};

use crate::{
    error::ApiError,
    models::user::{AuthProvider, LoginRequest, RegisterRequest, User, UserResponse},
    AppState,
};

// Auth response with token
#[derive(Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,
}

// Helper to extract token from Authorization header
fn extract_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

// Get current user
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserResponse>, ApiError> {
    let token = extract_token(&headers)
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    let claims = state.jwt.verify_token(&token)?;
    let user_id = ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("Invalid user ID".to_string()))?;

    let collection: Collection<User> = state.db.collection("users");
    let user = collection
        .find_one(doc! { "_id": user_id }, None)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    Ok(Json(UserResponse::from(user)))
}

// Email registration
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let collection: Collection<User> = state.db.collection("users");

    // Check if user exists
    if collection
        .find_one(doc! { "email": &req.email }, None)
        .await?
        .is_some()
    {
        return Err(ApiError::BadRequest("Email already registered".to_string()));
    }

    let password_hash = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST)
        .map_err(|e| ApiError::InternalError(format!("Password hash error: {}", e)))?;

    let now = bson::DateTime::now();
    let user = User {
        id: None,
        email: req.email.clone(),
        name: req.name,
        avatar_url: None,
        provider: AuthProvider::Email,
        provider_id: None,
        password_hash: Some(password_hash),
        created_at: now,
        updated_at: now,
    };

    let result = collection.insert_one(&user, None).await?;
    let user_id = result.inserted_id.as_object_id().unwrap();

    let token = state.jwt.create_token(&user_id, &req.email)?;

    let mut response_user = user;
    response_user.id = Some(user_id);

    Ok(Json(AuthResponse {
        user: UserResponse::from(response_user),
        token,
    }))
}

// Email login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let collection: Collection<User> = state.db.collection("users");

    let user = collection
        .find_one(doc! { "email": &req.email, "provider": "email" }, None)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Invalid credentials".to_string()))?;

    let password_hash = user
        .password_hash
        .as_ref()
        .ok_or_else(|| ApiError::Unauthorized("Invalid credentials".to_string()))?;

    if !bcrypt::verify(&req.password, password_hash)
        .map_err(|_| ApiError::Unauthorized("Invalid credentials".to_string()))?
    {
        return Err(ApiError::Unauthorized("Invalid credentials".to_string()));
    }

    let user_id = user
        .id
        .ok_or_else(|| ApiError::InternalError("User has no ID".to_string()))?;
    let token = state.jwt.create_token(&user_id, &user.email)?;

    Ok(Json(AuthResponse {
        user: UserResponse::from(user),
        token,
    }))
}

// Logout
pub async fn logout() -> impl IntoResponse {
    StatusCode::OK
}

// OAuth callback params
#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    code: String,
    #[allow(dead_code)]
    state: Option<String>,
}

// Google OAuth - redirect to consent
pub async fn google_auth(State(state): State<AppState>) -> Redirect {
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile&access_type=offline",
        state.config.google_client_id,
        urlencoding::encode(&state.config.google_redirect_url)
    );
    Redirect::to(&url)
}

// Google OAuth callback - returns token in URL
pub async fn google_callback(
    State(state): State<AppState>,
    Query(params): Query<OAuthCallback>,
) -> Result<Redirect, ApiError> {
    // Exchange code for token
    let client = reqwest::Client::new();
    let token_res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", params.code.as_str()),
            ("client_id", state.config.google_client_id.as_str()),
            ("client_secret", state.config.google_client_secret.as_str()),
            ("redirect_uri", state.config.google_redirect_url.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| ApiError::InternalError(format!("Token exchange failed: {}", e)))?;

    let token_data: serde_json::Value = token_res
        .json()
        .await
        .map_err(|e| ApiError::InternalError(format!("Token parse failed: {}", e)))?;

    let access_token = token_data["access_token"]
        .as_str()
        .ok_or_else(|| ApiError::InternalError("No access token".to_string()))?;

    // Get user info
    let user_res = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| ApiError::InternalError(format!("User info failed: {}", e)))?;

    let user_data: serde_json::Value = user_res
        .json()
        .await
        .map_err(|e| ApiError::InternalError(format!("User parse failed: {}", e)))?;

    let email = user_data["email"].as_str().unwrap_or_default().to_string();
    let name = user_data["name"].as_str().unwrap_or_default().to_string();
    let avatar_url = user_data["picture"].as_str().map(|s| s.to_string());
    let provider_id = user_data["id"].as_str().unwrap_or_default().to_string();

    let user = upsert_oauth_user(
        &state,
        email,
        name,
        avatar_url,
        AuthProvider::Google,
        provider_id,
    )
    .await?;

    let user_id = user
        .id
        .ok_or_else(|| ApiError::InternalError("User has no ID".to_string()))?;
    let token = state.jwt.create_token(&user_id, &user.email)?;

    // Redirect with token in URL to /app
    Ok(Redirect::to(&format!(
        "{}/app?token={}",
        state.config.frontend_url, token
    )))
}

// GitHub OAuth - redirect to consent
pub async fn github_auth(State(state): State<AppState>) -> Redirect {
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email",
        state.config.github_client_id,
        urlencoding::encode(&state.config.github_redirect_url)
    );
    Redirect::to(&url)
}

// GitHub OAuth callback - returns token in URL
pub async fn github_callback(
    State(state): State<AppState>,
    Query(params): Query<OAuthCallback>,
) -> Result<Redirect, ApiError> {
    let client = reqwest::Client::new();

    // Exchange code for token
    let token_res = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("code", params.code.as_str()),
            ("client_id", state.config.github_client_id.as_str()),
            ("client_secret", state.config.github_client_secret.as_str()),
        ])
        .send()
        .await
        .map_err(|e| ApiError::InternalError(format!("Token exchange failed: {}", e)))?;

    let token_data: serde_json::Value = token_res
        .json()
        .await
        .map_err(|e| ApiError::InternalError(format!("Token parse failed: {}", e)))?;

    let access_token = token_data["access_token"]
        .as_str()
        .ok_or_else(|| ApiError::InternalError("No access token".to_string()))?;

    // Get user info
    let user_res = client
        .get("https://api.github.com/user")
        .header("User-Agent", "Qlock-App")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| ApiError::InternalError(format!("User info failed: {}", e)))?;

    let user_data: serde_json::Value = user_res
        .json()
        .await
        .map_err(|e| ApiError::InternalError(format!("User parse failed: {}", e)))?;

    // Get email separately (might be private)
    let email_res = client
        .get("https://api.github.com/user/emails")
        .header("User-Agent", "Qlock-App")
        .bearer_auth(access_token)
        .send()
        .await
        .ok();

    let email = if let Some(res) = email_res {
        let emails: Vec<serde_json::Value> = res.json().await.unwrap_or_default();
        emails
            .iter()
            .find(|e| e["primary"].as_bool().unwrap_or(false))
            .and_then(|e| e["email"].as_str())
            .unwrap_or_else(|| user_data["email"].as_str().unwrap_or_default())
            .to_string()
    } else {
        user_data["email"].as_str().unwrap_or_default().to_string()
    };

    let name = user_data["name"]
        .as_str()
        .or(user_data["login"].as_str())
        .unwrap_or_default()
        .to_string();
    let avatar_url = user_data["avatar_url"].as_str().map(|s| s.to_string());
    let provider_id = user_data["id"].to_string();

    let user = upsert_oauth_user(
        &state,
        email,
        name,
        avatar_url,
        AuthProvider::Github,
        provider_id,
    )
    .await?;

    let user_id = user
        .id
        .ok_or_else(|| ApiError::InternalError("User has no ID".to_string()))?;
    let token = state.jwt.create_token(&user_id, &user.email)?;

    // Redirect with token in URL to /app
    Ok(Redirect::to(&format!(
        "{}/app?token={}",
        state.config.frontend_url, token
    )))
}

// Helper: Upsert OAuth user
async fn upsert_oauth_user(
    state: &AppState,
    email: String,
    name: String,
    avatar_url: Option<String>,
    provider: AuthProvider,
    provider_id: String,
) -> Result<User, ApiError> {
    let collection: Collection<User> = state.db.collection("users");
    let now = bson::DateTime::now();

    // Try to find existing user
    if let Some(mut user) = collection.find_one(doc! { "email": &email }, None).await? {
        // Update avatar and name
        collection
            .update_one(
                doc! { "_id": user.id },
                doc! { "$set": { "avatar_url": &avatar_url, "name": &name, "updated_at": now } },
                None,
            )
            .await?;
        user.avatar_url = avatar_url;
        user.name = name;
        return Ok(user);
    }

    // Create new user
    let user = User {
        id: None,
        email: email.clone(),
        name,
        avatar_url,
        provider,
        provider_id: Some(provider_id),
        password_hash: None,
        created_at: now,
        updated_at: now,
    };

    let result = collection.insert_one(&user, None).await?;
    let mut new_user = user;
    new_user.id = result.inserted_id.as_object_id();

    Ok(new_user)
}
