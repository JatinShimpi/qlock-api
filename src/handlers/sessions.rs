use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use axum_extra::extract::CookieJar;
use bson::{doc, oid::ObjectId};
use futures::StreamExt;
use mongodb::Collection;

use crate::{
    AppState,
    error::ApiError,
    models::session::{Attempt, ClientSession, Session, SessionResponse, SyncRequest},
};

use super::auth::extract_token;

// Helper to get user ID from token (checks cookie first, then Authorization header)
fn get_user_id(jar: &CookieJar, headers: &HeaderMap, state: &AppState) -> Result<ObjectId, ApiError> {
    let token = extract_token(jar, headers)
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    let claims = state.jwt.verify_token(&token)?;
    ObjectId::parse_str(&claims.sub)
        .map_err(|_| ApiError::Unauthorized("Invalid user ID".to_string()))
}

// List all sessions for user
pub async fn list_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let user_id = get_user_id(&jar, &headers, &state)?;
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
    headers: HeaderMap,
    Json(req): Json<SyncRequest>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let user_id = get_user_id(&jar, &headers, &state)?;
    let collection: Collection<Session> = state.db.collection("sessions");
    let now = bson::DateTime::now();

    for client_session in req.sessions {
        // Convert client attempts to server attempts first
        let new_attempts: Vec<Attempt> = client_session.attempts.iter().map(|a| {
            Attempt {
                id: a.id.clone(),
                date: parse_date(&a.date),
                results: a.results.clone(),
            }
        }).collect();

        // Check if already synced (by client_id)
        let existing = collection
            .find_one(doc! { "user_id": user_id, "client_id": &client_session.id }, None)
            .await?;

        if let Some(mut existing_session) = existing {
            // Merge attempts: Add only attempts that don't exist in the DB
            let mut changed = false;
            let existing_ids: Vec<String> = existing_session.attempts.iter().map(|a| a.id.clone()).collect();
            
            for attempt in new_attempts {
                if !existing_ids.contains(&attempt.id) {
                    existing_session.attempts.push(attempt);
                    changed = true;
                }
            }

            if changed {
                collection.update_one(
                    doc! { "_id": existing_session.id },
                    doc! { "$set": { 
                        "attempts": bson::to_bson(&existing_session.attempts).unwrap(),
                        "updated_at": now 
                    }},
                    None
                ).await?;
            }
            continue;
        }

        // New session: Create it
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
            attempts: new_attempts,
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

// Create a new session
pub async fn create_session(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(client_session): Json<ClientSession>,
) -> Result<Json<SessionResponse>, ApiError> {
    let user_id = get_user_id(&jar, &headers, &state)?;
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

    // Check if session with this client_id already exists
    let existing = collection
        .find_one(doc! { "user_id": user_id, "client_id": &client_session.id }, None)
        .await?;

    if let Some(mut existing_session) = existing {
        // Update existing session
        let mut changed = false;
        
        // Update fields that might have changed
        if existing_session.topic != client_session.topic { existing_session.topic = client_session.topic; changed = true; }
        if existing_session.subtopic != client_session.subtopic { existing_session.subtopic = client_session.subtopic; changed = true; }
        if existing_session.timer_mode != client_session.timer_mode { existing_session.timer_mode = client_session.timer_mode; changed = true; }
        if existing_session.time_per_question != client_session.time_per_question { existing_session.time_per_question = client_session.time_per_question; changed = true; }
        if existing_session.total_time != client_session.total_time { existing_session.total_time = client_session.total_time; changed = true; }

        // Merge attempts
        let existing_ids: Vec<String> = existing_session.attempts.iter().map(|a| a.id.clone()).collect();
        for attempt in attempts {
            if !existing_ids.contains(&attempt.id) {
                existing_session.attempts.push(attempt);
                changed = true;
            }
        }

        if changed {
            collection.update_one(
                doc! { "_id": existing_session.id },
                doc! { "$set": { 
                    "topic": &existing_session.topic,
                    "subtopic": &existing_session.subtopic,
                    "timer_mode": &existing_session.timer_mode,
                    "time_per_question": &existing_session.time_per_question,
                    "total_time": &existing_session.total_time,
                    "attempts": bson::to_bson(&existing_session.attempts).unwrap(),
                    "updated_at": now 
                }},
                None
            ).await?;
        }
        
        return Ok(Json(SessionResponse::from(existing_session)));
    }

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
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(client_session): Json<ClientSession>,
) -> Result<Json<SessionResponse>, ApiError> {
    let user_id = get_user_id(&jar, &headers, &state)?;
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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<(), ApiError> {
    let user_id = get_user_id(&jar, &headers, &state)?;
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
