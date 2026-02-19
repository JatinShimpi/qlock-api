use bson::oid::ObjectId;
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
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synced_at: Option<bson::DateTime>,
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
    pub date: bson::DateTime,
    pub results: Vec<AttemptResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptResult {
    #[serde(alias = "question_id", rename = "questionId")]
    pub question_id: String,
    #[serde(default)]
    pub identifier: String,
    pub status: String,
    #[serde(alias = "time_taken", rename = "timeTaken")]
    pub time_taken: i32,
    #[serde(alias = "total_time", rename = "totalTime", skip_serializing_if = "Option::is_none")]
    pub total_time: Option<i32>,
    #[serde(alias = "user_answer", rename = "userAnswer", skip_serializing_if = "Option::is_none")]
    pub user_answer: Option<serde_json::Value>,
    #[serde(alias = "question_type", rename = "questionType", skip_serializing_if = "Option::is_none")]
    pub question_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "id")]
    pub client_id: String,
    pub topic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtopic: Option<String>,
    #[serde(rename = "timerMode")]
    pub timer_mode: String,
    #[serde(rename = "timePerQuestion")]
    pub time_per_question: i32,
    #[serde(rename = "totalTime", skip_serializing_if = "Option::is_none")]
    pub total_time: Option<i32>,
    pub questions: Vec<Question>,
    pub attempts: Vec<Attempt>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
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
            created_at: s.created_at.try_to_rfc3339_string().unwrap_or_default(),
            updated_at: s.updated_at.try_to_rfc3339_string().unwrap_or_default(),
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
    pub attempts: Vec<ClientAttempt>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientAttempt {
    pub id: String,
    pub date: String,  // ISO string from client
    pub results: Vec<AttemptResult>,
}
