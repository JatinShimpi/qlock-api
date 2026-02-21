use axum::{
    extract::{Query, State},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Redirect},
    Json,
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use bson::{doc, oid::ObjectId};
use mongodb::Collection;
use serde::{Deserialize, Serialize};
use time::Duration;

use crate::{
    config::Config,
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

// Helper to extract token from cookie (web) or Authorization header (mobile)
pub fn extract_token(jar: &CookieJar, headers: &HeaderMap) -> Option<String> {
    // 1. Check HTTP-only cookie (web clients)
    if let Some(cookie) = jar.get("auth_token") {
        return Some(cookie.value().to_string());
    }
    // 2. Fall back to Authorization header (mobile clients)
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

// Helper to build an HTTP-only auth cookie
pub fn build_auth_cookie(token: &str, config: &Config) -> Cookie<'static> {
    Cookie::build(("auth_token", token.to_string()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .path("/")
        .max_age(Duration::hours(config.jwt_expiry_hours))
        .build()
}

// Helper to build a cookie that clears the auth token
pub fn clear_auth_cookie() -> Cookie<'static> {
    Cookie::build(("auth_token", ""))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .path("/")
        .max_age(Duration::ZERO)
        .build()
}

// Get current user
pub async fn me(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<UserResponse>, ApiError> {
    let token = extract_token(&jar, &headers)
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
) -> Result<(CookieJar, Json<AuthResponse>), ApiError> {
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
    let jar = CookieJar::new().add(build_auth_cookie(&token, &state.config));

    let mut response_user = user;
    response_user.id = Some(user_id);

    Ok((jar, Json(AuthResponse {
        user: UserResponse::from(response_user),
        token,
    })))
}

// Email login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<AuthResponse>), ApiError> {
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
    let jar = CookieJar::new().add(build_auth_cookie(&token, &state.config));

    Ok((jar, Json(AuthResponse {
        user: UserResponse::from(user),
        token,
    })))
}

// Logout — clears the HTTP-only auth cookie
pub async fn logout() -> impl IntoResponse {
    let jar = CookieJar::new().add(clear_auth_cookie());
    (jar, StatusCode::OK)
}

// OAuth callback params
#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    code: String,
    state: Option<String>,
}

// Google OAuth - redirect to consent
pub async fn google_auth(State(state): State<AppState>) -> (CookieJar, Redirect) {
    let oauth_state = uuid::Uuid::new_v4().to_string();
    let cookie = Cookie::build(("oauth_state", oauth_state.clone()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::minutes(10))
        .build();

    let url = format!(
         "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile&access_type=offline&state={}",
        state.config.google_client_id,
        urlencoding::encode(&state.config.google_redirect_url),
        urlencoding::encode(&oauth_state)
    );
    (CookieJar::new().add(cookie), Redirect::to(&url))
}

// Google OAuth callback - sets HTTP-only cookie and redirects
pub async fn google_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<OAuthCallback>,
) -> Result<(CookieJar, Redirect), ApiError> {
    // Validate OAuth state to prevent CSRF
    let state_cookie = jar.get("oauth_state").map(|c| c.value().to_string());
    if state_cookie.is_none() || params.state.is_none() || state_cookie != params.state {
        return Err(ApiError::Unauthorized("Invalid or missing OAuth state parameter".to_string()));
    }

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

    // Set HTTP-only cookie and redirect (no token in URL)
    let jar = CookieJar::new().add(build_auth_cookie(&token, &state.config));
    Ok((jar, Redirect::to(&state.config.frontend_url)))
}

// Mobile Google Auth Request
#[derive(Debug, Deserialize)]
pub struct MobileGoogleAuthRequest {
    #[serde(rename = "idToken")]
    id_token: String,
}

// Google Token Info Response
#[derive(Debug, Deserialize)]
struct GoogleTokenInfo {
    email: Option<String>,
    name: Option<String>,
    picture: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
}

// Mobile Google Auth - verify ID token from native apps
pub async fn google_mobile_auth(
    State(state): State<AppState>,
    Json(req): Json<MobileGoogleAuthRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Verify the ID token with Google
    let client = reqwest::Client::new();
    let token_info_res = client
        .get(&format!(
            "https://oauth2.googleapis.com/tokeninfo?id_token={}",
            req.id_token
        ))
        .send()
        .await
        .map_err(|e| ApiError::InternalError(format!("Token verification failed: {}", e)))?;

    if !token_info_res.status().is_success() {
        return Err(ApiError::Unauthorized("Invalid Google ID token".to_string()));
    }

    let token_info: GoogleTokenInfo = token_info_res
        .json()
        .await
        .map_err(|e| ApiError::InternalError(format!("Token parse failed: {}", e)))?;

    if let Some(aud) = &token_info.aud {
        if aud != &state.config.google_client_id {
            return Err(ApiError::Unauthorized("Invalid token audience".to_string()));
        }
    } else {
        return Err(ApiError::Unauthorized("Token misses audience".to_string()));
    }

    let email = token_info
        .email
        .ok_or_else(|| ApiError::BadRequest("No email in token".to_string()))?;
    let name = token_info.name.unwrap_or_else(|| email.clone());
    let avatar_url = token_info.picture;
    let provider_id = token_info.sub.unwrap_or_default();

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

    Ok(Json(AuthResponse {
        user: UserResponse::from(user),
        token,
    }))
}

// GitHub OAuth - redirect to consent
pub async fn github_auth(State(state): State<AppState>) -> (CookieJar, Redirect) {
    let oauth_state = uuid::Uuid::new_v4().to_string();
    let cookie = Cookie::build(("oauth_state", oauth_state.clone()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::minutes(10))
        .build();

    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
        state.config.github_client_id,
        urlencoding::encode(&state.config.github_redirect_url),
        urlencoding::encode(&oauth_state)
    );
    (CookieJar::new().add(cookie), Redirect::to(&url))
}

// GitHub OAuth callback - sets HTTP-only cookie and redirects
pub async fn github_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<OAuthCallback>,
) -> Result<(CookieJar, Redirect), ApiError> {
    // Validate OAuth state to prevent CSRF
    let state_cookie = jar.get("oauth_state").map(|c| c.value().to_string());
    if state_cookie.is_none() || params.state.is_none() || state_cookie != params.state {
        return Err(ApiError::Unauthorized("Invalid or missing OAuth state parameter".to_string()));
    }

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
        let verified_email = emails
            .iter()
            .find(|e| e["primary"].as_bool().unwrap_or(false) && e["verified"].as_bool().unwrap_or(false))
            .and_then(|e| e["email"].as_str());
        
        if let Some(e) = verified_email {
            e.to_string()
        } else {
            return Err(ApiError::Unauthorized("No verified primary email found on GitHub".to_string()));
        }
    } else {
        return Err(ApiError::Unauthorized("Failed to fetch emails from GitHub".to_string()));
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

    // Set HTTP-only cookie and redirect (no token in URL)
    let jar = CookieJar::new().add(build_auth_cookie(&token, &state.config));
    Ok((jar, Redirect::to(&state.config.frontend_url)))
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
