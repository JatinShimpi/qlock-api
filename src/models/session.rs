use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub user_id: ObjectId,
    pub client_id: String,  // Original ID from localStorage
    pub topic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtopic: Option<String>,
    pub timer_mode: String,
    pub time_per_question: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_time: Option<i32>,
    pub questions: Vec<Question>,
    pub attempts: Vec<Attempt>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Question {
    pub id: String,
    pub identifier: String,
    pub time: i32,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub question_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attempt {
    pub id: String,
    pub date: DateTime<Utc>,
    pub results: Vec<AttemptResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptResult {
    pub question_id: String,
    pub identifier: String,
    pub status: String,
    pub time_taken: i32,
    pub total_time: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_answer: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: String,
    pub client_id: String,
    pub topic: String,
    pub subtopic: Option<String>,
    pub timer_mode: String,
    pub time_per_question: i32,
    pub total_time: Option<i32>,
    pub questions: Vec<Question>,
    pub attempts: Vec<Attempt>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Session> for SessionResponse {
    fn from(s: Session) -> Self {
        Self {
            id: s.id.map(|id| id.to_hex()).unwrap_or_default(),
            client_id: s.client_id,
            topic: s.topic,
            subtopic: s.subtopic,
            timer_mode: s.timer_mode,
            time_per_question: s.time_per_question,
            total_time: s.total_time,
            questions: s.questions,
            attempts: s.attempts,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SyncRequest {
    pub sessions: Vec<ClientSession>,
}

#[derive(Debug, Deserialize)]
pub struct ClientSession {
    pub id: String,
    pub topic: String,
    pub subtopic: Option<String>,
    #[serde(rename = "timerMode")]
    pub timer_mode: String,
    #[serde(rename = "timePerQuestion")]
    pub time_per_question: i32,
    #[serde(rename = "totalTime")]
    pub total_time: Option<i32>,
    pub questions: Vec<Question>,
    pub attempts: Vec<Attempt>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
}
