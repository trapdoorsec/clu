//! clu-api: Sidecar REST API service for findings triage.
//!
//! This binary starts an axum HTTP server that stores and serves malware scan
//! findings. It shares the SQLite database with the clu scanner (WAL mode).

use clu::config::Config;
use clu::db::Database;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let config = match Config::load("config.toml") {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    let listen_addr = config.sidecar.listen_addr.clone();
    let db = match Database::new(&config.database.url).await {
        Ok(db) => db,
        Err(e) => {
            log::error!("Failed to open database: {}", e);
            std::process::exit(1);
        }
    };

    let app = clu::api::router(db, config.sidecar.token.clone());

    log::info!("clu-api listening on {}", listen_addr);
    let listener = tokio::net::TcpListener::bind(&listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
