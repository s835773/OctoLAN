use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use tracing::{info, debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub vendor: String,
    pub rtt_ms: f64,
}

/// Resolves MAC OUI prefix to hardware manufacturer
pub fn resolve_vendor_oui(mac_str: &str) -> String {
    let clean = mac_str.to_lowercase().replace(":", "").replace("-", "");
    if clean.len() < 6 { return "Generic Network Host".to_string(); }
    let oui = &clean[0..6];
    
    match oui {
        "bca9d4" | "001b21" => "Cisco Systems Enterprise".to_string(),
        "000c29" | "005056" => "VMware ESXi Virtualization".to_string(),
        "b827eb" | "dca632" => "Raspberry Pi Foundation".to_string(),
        "d85ed3" | "1866da" => "Dell Inc. Enterprise Servers".to_string(),
        "3c22fb" | "f01898" => "Apple Inc.".to_string(),
        "e4aa5d" | "0026f2" => "Netgear Managed Switch".to_string(),
        "708105" => "FreePBX / Digium VoIP".to_string(),
        _ => "Standard IEEE 802.3 Node".to_string(),
    }
}

/// Standalone CLI ARP sweep runner
pub async fn run_cli_arp_sweep(iface_name: &str, _subnet: &str) -> Result<Vec<DiscoveredHost>, Box<dyn std::error::Error>> {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == iface_name)
        .ok_or_else(|| format!("Interface '{}' not found", iface_name))?;

    info!("Using interface: {} (MAC: {:?})", interface.name, interface.mac);
    
    let base_octets: [u8; 4] = [192, 168, 1, 0];
    let mut discovered = Vec::new();

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unhandled datalink channel type".into()),
        Err(e) => return Err(format!("Failed to open AF_PACKET raw socket: {}. Try running with sudo/CAP_NET_RAW.", e).into()),
    };

    let start_time = Instant::now();

    // Transmit ARP requests across the /24 prefix
    for host_id in 1..=254 {
        let target_ip = Ipv4Addr::new(base_octets[0], base_octets[1], base_octets[2], host_id);
        let mut eth_buf = [0u8; 42];
        
        let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
        eth_pkt.set_destination(MacAddr::broadcast());
        eth_pkt.set_source(interface.mac.unwrap_or(MacAddr::zero()));
        eth_pkt.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0u8; 28];
        let mut arp_pkt = MutableArpPacket::new(&mut arp_buf).unwrap();
        arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_pkt.set_protocol_type(EtherTypes::Ipv4);
        arp_pkt.set_hw_addr_len(6);
        arp_pkt.set_proto_addr_len(4);
        arp_pkt.set_operation(ArpOperations::Request);
        arp_pkt.set_sender_hw_addr(interface.mac.unwrap_or(MacAddr::zero()));
        arp_pkt.set_sender_proto_addr(Ipv4Addr::new(192, 168, 1, 5));
        arp_pkt.set_target_hw_addr(MacAddr::zero());
        arp_pkt.set_target_proto_addr(target_ip);

        eth_pkt.set_payload(arp_pkt.packet());
        let _ = tx.send_to(eth_pkt.packet(), None);
    }

    // Read responses with a 1.5-second timeout window
    let rx_deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < rx_deadline {
        if let Ok(packet) = rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply {
                            let ip = arp.get_sender_proto_addr();
                            let mac = arp.get_sender_hw_addr().to_string();
                            let vendor = resolve_vendor_oui(&mac);
                            let rtt_ms = (Instant::now() - start_time).as_secs_f64() * 1000.0 / 10.0;

                            info!("[+] Host Discovered: {:<15} at {} ({})", ip, mac, vendor);
                            discovered.push(DiscoveredHost { ip, mac, vendor, rtt_ms });
                        }
                    }
                }
            }
        }
    }

    info!("Sweep complete: {} active hosts discovered.", discovered.len());
    Ok(discovered)
}
