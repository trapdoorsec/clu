//! clu-api: Sidecar REST API service for findings triage.
//!
//! This binary starts an axum HTTP server that stores and serves malware scan
//! findings. It shares the SQLite database with the clu scanner (WAL mode).
//!
//! When a `static_dir` is configured (or the `ui/` directory exists at runtime),
//! the server also serves the SPA frontend at `/` with a fallback to
//! `index.html` for client-side routing. API routes live under `/api/`.

use clu::api::{is_loopback, router};
use clu::config::Config;
use clu::db::Database;
use metrics_exporter_prometheus::PrometheusBuilder;

/// Directory where the built SPA assets are expected.
const STATIC_DIR: &str = "ui/dist";

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

    if config.sidecar.token.is_none() && !is_loopback(&listen_addr) {
        log::error!(
            "FATAL: No auth token configured and bind address {:?} is not loopback. \
             Set [sidecar] token in config.toml or bind to 127.0.0.1.",
            listen_addr
        );
        std::process::exit(1);
    }

    let db = match Database::new(&config.database.url).await {
        Ok(db) => db,
        Err(e) => {
            log::error!("Failed to open database: {}", e);
            std::process::exit(1);
        }
    };

    let prometheus_handle = PrometheusBuilder::new().install_recorder().ok();

    metrics::counter!("clu_findings_total").increment(0);

    let api_router = router(
        db,
        config.sidecar.token.clone(),
        listen_addr.clone(),
        prometheus_handle,
    );

    let static_path = std::path::PathBuf::from(STATIC_DIR);
    let serve_spa = static_path.is_dir();

    let app = if serve_spa {
        log::info!("Serving SPA frontend from {}", STATIC_DIR);
        let spa_service = tower_http::services::ServeDir::new(&static_path)
            .fallback(tower_http::services::ServeFile::new(
                static_path.join("index.html"),
            ));
        api_router.fallback_service(spa_service)
    } else {
        log::info!("No SPA directory found at {}, serving API only", STATIC_DIR);
        api_router
    };

    log::info!("clu-api listening on {}", listen_addr);
    let listener = tokio::net::TcpListener::bind(&listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
