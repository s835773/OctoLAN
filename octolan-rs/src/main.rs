// octolan-rs: High-performance async LAN telemetry and reconnaissance daemon
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use clap::{Parser, Subcommand};
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

mod api;
mod scanners;

#[derive(Parser, Debug)]
#[command(name = "octolan-rs", version = "2.1.0", about = "Asynchronous Network Reconnaissance Daemon")]
pub struct CliArgs {
    #[arg(short, long, default_value = "eth0", help = "Network interface to attach raw socket")]
    pub interface: String,

    #[arg(short, long, default_value_t = 3000, help = "HTTP & WebSocket listening port")]
    pub port: u16,

    #[arg(long, default_value = "0.0.0.0", help = "Bind address")]
    pub host: String,

    #[arg(long, default_value_t = 2055, help = "UDP port for NetFlow v5/v9 collector")]
    pub netflow_port: u16,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Perform a standalone fast ARP subnet sweep
    Scan {
        #[arg(short, long, default_value = "192.168.1.0/24")]
        subnet: String,
    },
    /// Monitor broadcast storms & packet per second spikes
    StormWatch {
        #[arg(short, long, default_value_t = 2200)]
        threshold_pps: u32,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize structured logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = CliArgs::parse();
    info!("🚀 Initializing octolan-rs v2.1.0 (Tokio Multi-Core Runtime)");

    // 2. Broadcast channel for real-time telemetry streaming to WebSockets
    let (tx_telemetry, _) = broadcast::channel::<String>(256);
    let tx_telemetry = Arc::new(tx_telemetry);

    // 3. Handle standalone CLI subcommands if requested
    if let Some(cmd) = args.command {
        match cmd {
            Commands::Scan { subnet } => {
                info!("🔍 Launching CLI ARP Sweep on {} for {}", args.interface, subnet);
                scanners::arp::run_cli_arp_sweep(&args.interface, &subnet).await?;
                return Ok(());
            }
            Commands::StormWatch { threshold_pps } => {
                info!("⚡ Launching Storm Watchdog (Threshold: {} PPS)", threshold_pps);
                scanners::storm::run_cli_storm_watch(&args.interface, threshold_pps).await?;
                return Ok(());
            }
        }
    }

    // 4. Spawn Background Async Tasks
    // Task A: Real-time NetFlow UDP Ingestion Engine (Port 2055)
    let nf_tx = tx_telemetry.clone();
    let nf_port = args.netflow_port;
    tokio::spawn(async move {
        if let Err(e) = scanners::netflow::start_netflow_collector(nf_port, nf_tx).await {
            error!("NetFlow collector failed: {}", e);
        }
    });

    // Task B: Real-time PPS & Broadcast Storm Monitor
    let storm_tx = tx_telemetry.clone();
    let iface_name = args.interface.clone();
    tokio::spawn(async move {
        if let Err(e) = scanners::storm::start_storm_monitor(&iface_name, 2200, storm_tx).await {
            warn!("Storm monitor fallback to synthetic tap (requires CAP_NET_RAW): {}", e);
        }
    });

    // 5. Start Axum HTTP & WebSocket Server
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    info!("🌐 Starting Axum REST & WebSocket Server at http://{}", addr);
    info!("📡 Streaming real-time telemetry on ws://{}/ws/telemetry", addr);

    let app = api::create_router(args.interface.clone(), tx_telemetry);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("🛑 octolan-rs gracefully stopped.");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C signal handler");
    info!("Received Ctrl+C shutdown signal");
}
