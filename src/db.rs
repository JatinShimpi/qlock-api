use mongodb::{Client, Database};
use std::sync::Arc;

use crate::config::Config;

pub type DbPool = Arc<Database>;

pub async fn connect(config: &Config) -> DbPool {
    let client = Client::with_uri_str(&config.mongodb_uri)
        .await
        .expect("Failed to connect to MongoDB");

    let db = client.database(&config.database_name);
    
    tracing::info!("Connected to MongoDB database: {}", config.database_name);
    
    Arc::new(db)
}
