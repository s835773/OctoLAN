pub mod ws;

use axum::{
    routing::{get, post},
    Router, Json, extract::State,
};
use tower_http::cors::{CorsLayer, Any};
use std::sync::Arc;
use tokio::sync::broadcast;
use serde_json::json;

use self::ws::{ws_handler, AppState};
use crate::scanners::arp;

pub fn create_router(interface: String, tx_telemetry: Arc<broadcast::Sender<String>>) -> Router {
    let state = AppState {
        interface,
        tx_telemetry,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/status", get(status_handler))
        .route("/api/scan", post(scan_handler))
        .route("/ws/telemetry", get(ws_handler))
        .layer(cors)
        .with_state(state)
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "runtime": "Rust 1.80+ / Axum v0.7 / Tokio",
        "engine": "octolan-rs",
        "version": "2.1.0"
    }))
}

async fn status_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "online",
        "interface": state.interface,
        "mode": "Promiscuous Layer-2 Tap",
        "netflow_port": 2055,
        "capabilities": ["CAP_NET_RAW", "CAP_NET_ADMIN"],
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH
    }))
}

async fn scan_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Perform on-demand ARP sweep
    match arp::run_cli_arp_sweep(&state.interface, "192.168.1.0/24").await {
        Ok(hosts) => Json(json!({
            "success": true,
            "discovered_count": hosts.len(),
            "hosts": hosts
        })),
        Err(e) => Json(json!({
            "success": false,
            "error": e.to_string()
        }))
    }
}
