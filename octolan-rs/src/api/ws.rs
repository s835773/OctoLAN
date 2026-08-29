use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, debug};

#[derive(Clone)]
pub struct AppState {
    pub interface: String,
    pub tx_telemetry: Arc<broadcast::Sender<String>>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx_telemetry.subscribe();

    info!("📡 Client established real-time WebSocket connection");

    // Task 1: Forward background broadcast channel events to this WebSocket client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // Task 2: Listen for incoming client commands (e.g. request on-demand ARP sweep)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                debug!("Received command from client: {}", text);
            }
        }
    });

    // Terminate tasks when either client disconnects or channel breaks
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    info!("🔌 WebSocket client disconnected");
}
