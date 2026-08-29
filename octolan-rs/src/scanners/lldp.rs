use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldpNeighbor {
    pub chassis_id: String,
    pub port_id: String,
    pub system_name: String,
    pub system_description: String,
    pub vlan_id: u16,
}

pub fn parse_simulated_lldp_frame() -> Vec<LldpNeighbor> {
    vec![
        LldpNeighbor {
            chassis_id: "bc:a9:d4:11:22:00".to_string(),
            port_id: "GigabitEthernet0/1".to_string(),
            system_name: "core-sw01.corp.local".to_string(),
            system_description: "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M)".to_string(),
            vlan_id: 10,
        },
        LldpNeighbor {
            chassis_id: "00:1b:21:44:55:00".to_string(),
            port_id: "GigabitEthernet0/24".to_string(),
            system_name: "dist-sw02.corp.local".to_string(),
            system_description: "Cisco Catalyst 2960-X Series".to_string(),
            vlan_id: 30,
        },
    ]
}
