use axum::{
    extract::{Path, State},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use bson::{doc, oid::ObjectId};
use futures::StreamExt;
use mongodb::Collection;

use crate::{
    AppState,
    error::ApiError,
    models::session::{Attempt, ClientSession, Session, SessionResponse, SyncRequest},
};

// Helper to get user ID from token
fn get_user_id(jar: &CookieJar, state: &AppState) -> Result<ObjectId, ApiError> {
    let token = jar
        .get("auth_token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    let claims = state.jwt.verify_token(&token)?;
    ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("Invalid user ID".to_string()))
}

// List all sessions for user
pub async fn list_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let user_id = get_user_id(&jar, &state)?;
    let collection: Collection<Session> = state.db.collection("sessions");

    let mut cursor = collection.find(doc! { "user_id": user_id }, None).await?;
    let mut sessions = Vec::new();

    while let Some(result) = cursor.next().await {
        if let Ok(session) = result {
            sessions.push(SessionResponse::from(session));
        }
    }

    Ok(Json(sessions))
}

// Parse ISO date string to bson::DateTime
fn parse_date(s: &str) -> bson::DateTime {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| bson::DateTime::from_chrono(d.with_timezone(&chrono::Utc)))
        .unwrap_or_else(|_| bson::DateTime::now())
}

// Sync local sessions to cloud (one-time migration)
pub async fn sync_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<SyncRequest>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let user_id = get_user_id(&jar, &state)?;
    let collection: Collection<Session> = state.db.collection("sessions");
    let now = bson::DateTime::now();

    for client_session in req.sessions {
        // Check if already synced (by client_id)
        let existing = collection
            .find_one(doc! { "user_id": user_id, "client_id": &client_session.id }, None)
            .await?;

        if existing.is_some() {
            continue; // Skip already synced
        }

        // Convert client attempts to server attempts
        let attempts: Vec<Attempt> = client_session.attempts.iter().map(|a| {
            Attempt {
                id: a.id.clone(),
                date: parse_date(&a.date),
                results: a.results.clone(),
            }
        }).collect();

        let session = Session {
            id: None,
            user_id,
            client_id: client_session.id,
            topic: client_session.topic,
            subtopic: client_session.subtopic,
            timer_mode: client_session.timer_mode,
            time_per_question: client_session.time_per_question,
            total_time: client_session.total_time,
            questions: client_session.questions,
            attempts,
            created_at: client_session.created_at
                .as_ref()
                .map(|s| parse_date(s))
                .unwrap_or(now),
            updated_at: now,
            synced_at: Some(now),
        };

        collection.insert_one(&session, None).await?;
    }

    // Return all sessions
    list_sessions(State(state), jar).await
}

// Create a new session
pub async fn create_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(client_session): Json<ClientSession>,
) -> Result<Json<SessionResponse>, ApiError> {
    let user_id = get_user_id(&jar, &state)?;
    let collection: Collection<Session> = state.db.collection("sessions");
    let now = bson::DateTime::now();

    // Convert client attempts to server attempts
    let attempts: Vec<Attempt> = client_session.attempts.iter().map(|a| {
        Attempt {
            id: a.id.clone(),
            date: parse_date(&a.date),
            results: a.results.clone(),
        }
    }).collect();

    let session = Session {
        id: None,
        user_id,
        client_id: client_session.id,
        topic: client_session.topic,
        subtopic: client_session.subtopic,
        timer_mode: client_session.timer_mode,
        time_per_question: client_session.time_per_question,
        total_time: client_session.total_time,
        questions: client_session.questions,
        attempts,
        created_at: now,
        updated_at: now,
        synced_at: Some(now),
    };

    let result = collection.insert_one(&session, None).await?;
    let mut saved = session;
    saved.id = result.inserted_id.as_object_id();

    Ok(Json(SessionResponse::from(saved)))
}

// Update a session
pub async fn update_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(client_session): Json<ClientSession>,
) -> Result<Json<SessionResponse>, ApiError> {
    let user_id = get_user_id(&jar, &state)?;
    let session_id = ObjectId::parse_str(&id)
        .map_err(|_| ApiError::BadRequest("Invalid session ID".to_string()))?;

    let collection: Collection<Session> = state.db.collection("sessions");
    let now = bson::DateTime::now();

    // Verify ownership
    let existing = collection
        .find_one(doc! { "_id": session_id, "user_id": user_id }, None)
        .await?
        .ok_or_else(|| ApiError::NotFound("Session not found".to_string()))?;

    // Convert client attempts to server attempts
    let attempts: Vec<Attempt> = client_session.attempts.iter().map(|a| {
        Attempt {
            id: a.id.clone(),
            date: parse_date(&a.date),
            results: a.results.clone(),
        }
    }).collect();

    collection.update_one(
        doc! { "_id": session_id },
        doc! { "$set": {
            "topic": &client_session.topic,
            "subtopic": &client_session.subtopic,
            "timer_mode": &client_session.timer_mode,
            "time_per_question": client_session.time_per_question,
            "total_time": client_session.total_time,
            "questions": bson::to_bson(&client_session.questions).unwrap(),
            "attempts": bson::to_bson(&attempts).unwrap(),
            "updated_at": now,
        }},
        None
    ).await?;

    let updated = Session {
        id: Some(session_id),
        user_id,
        client_id: existing.client_id,
        topic: client_session.topic,
        subtopic: client_session.subtopic,
        timer_mode: client_session.timer_mode,
        time_per_question: client_session.time_per_question,
        total_time: client_session.total_time,
        questions: client_session.questions,
        attempts,
        created_at: existing.created_at,
        updated_at: now,
        synced_at: Some(now),
    };

    Ok(Json(SessionResponse::from(updated)))
}

// Delete a session
pub async fn delete_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> Result<(), ApiError> {
    let user_id = get_user_id(&jar, &state)?;
    let session_id = ObjectId::parse_str(&id)
        .map_err(|_| ApiError::BadRequest("Invalid session ID".to_string()))?;

    let collection: Collection<Session> = state.db.collection("sessions");

    let result = collection
        .delete_one(doc! { "_id": session_id, "user_id": user_id }, None)
        .await?;

    if result.deleted_count == 0 {
        return Err(ApiError::NotFound("Session not found".to_string()));
    }

    Ok(())
}
