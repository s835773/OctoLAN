use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetflowRecordJson {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packets: u32,
    pub bytes: u32,
    pub vlan_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPacket {
    pub r#type: String,
    pub timestamp: String,
    pub current_pps: u64,
    pub flow_count: usize,
    pub recent_flows: Vec<NetflowRecordJson>,
}

pub async fn start_netflow_collector(
    port: u16, 
    tx_stream: Arc<broadcast::Sender<String>>
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&bind_addr).await?;
    info!("📡 NetFlow UDP Ingestion daemon listening on {}", bind_addr);

    let mut buf = [0u8; 65535];
    let packet_counter = Arc::new(AtomicU64::new(0));

    // Spawn 1-second interval ticker for computing instant PPS
    let ticker_counter = packet_counter.clone();
    let ticker_tx = tx_stream.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        let mut prev = 0u64;
        loop {
            interval.tick().await;
            let current = ticker_counter.load(Ordering::Relaxed);
            let pps = current.saturating_sub(prev);
            prev = current;

            let msg = serde_json::json!({
                "type": "pps_update",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "pps": pps,
                "total_packets": current
            });
            let _ = ticker_tx.send(msg.to_string());
        }
    });

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _src)) => {
                if len < 24 { continue; }
                
                let version = u16::from_be_bytes([buf[0], buf[1]]);
                let count = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                
                packet_counter.fetch_add(count as u64, Ordering::Relaxed);

                if version == 5 {
                    let mut flows = Vec::new();
                    let record_size = 48;

                    for i in 0..count.min(30) {
                        let offset = 24 + i * record_size;
                        if offset + record_size > len { break; }

                        let src_ip = Ipv4Addr::new(buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]);
                        let dst_ip = Ipv4Addr::new(buf[offset+4], buf[offset+5], buf[offset+6], buf[offset+7]);
                        let packets = u32::from_be_bytes([buf[offset+16], buf[offset+17], buf[offset+18], buf[offset+19]]);
                        let bytes = u32::from_be_bytes([buf[offset+20], buf[offset+21], buf[offset+22], buf[offset+23]]);
                        let src_port = u16::from_be_bytes([buf[offset+32], buf[offset+33]]);
                        let dst_port = u16::from_be_bytes([buf[offset+34], buf[offset+35]]);
                        let proto_num = buf[offset+38];

                        let protocol = match proto_num {
                            6 => "TCP".to_string(),
                            17 => "UDP".to_string(),
                            1 => "ICMP".to_string(),
                            _ => format!("IP/{}", proto_num),
                        };

                        flows.push(NetflowRecordJson {
                            src_ip: src_ip.to_string(),
                            dst_ip: dst_ip.to_string(),
                            src_port,
                            dst_port,
                            protocol,
                            packets,
                            bytes,
                            vlan_id: 10,
                        });
                    }

                    let payload = TelemetryPacket {
                        r#type: "netflow_batch".to_string(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        current_pps: packet_counter.load(Ordering::Relaxed),
                        flow_count: flows.len(),
                        recent_flows: flows,
                    };

                    if let Ok(json_str) = serde_json::to_string(&payload) {
                        let _ = tx_stream.send(json_str);
                    }
                }
            }
            Err(e) => {
                warn!("NetFlow UDP socket error: {}", e);
            }
        }
    }
}
