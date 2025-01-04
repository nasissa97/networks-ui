use std::net::{IpAddr, Ipv4Addr};
use pnet::util::MacAddr;
use tokio::net::{lookup_host, TcpStream};
use ipnetwork::IpNetwork;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use std::collections::HashSet;
use tokio::task;

/// Perform a reverse DNS lookup for an IP address.
async fn get_device_name(ip: IpAddr) -> Option<String> {
    match lookup_host((ip, 0)).await {
        Ok(mut results) => {
            if let Some(addr) = results.next() {
                return Some(addr.to_string());
            }
        }
        Err(_) => {}
    }
    None
}


fn get_network_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .filter(|iface| iface.is_up() && !iface.is_loopback())
        .collect()
}

/// Get all IP networks associated with an interface
fn get_ip_networks(interface: &NetworkInterface) -> Vec<IpNetwork> {
    interface.ips.clone()
}

async fn scan_ip(ip: IpAddr) -> bool {
    match TcpStream::connect((ip, 80)).await {
        Ok(_) => {
            println!("✅ Device found at IP: {}", ip);
            true
        }
        Err(_) => false,
    }
}

fn send_arp_request(interface: &NetworkInterface, target_ip: Ipv4Addr) -> Option<(Ipv4Addr, String)> {
    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unsupported channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    // Define source MAC and IP
    let source_mac = interface.mac.unwrap();
    let source_ip = interface.ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .and_then(|ip| match ip.ip() {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        }).expect("No IPv4 address found on the interface");

    // Build Ethernet Frame
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination([0xff; 6].into()); // Broacdcast MAC
    ethernet_packet.set_source(source_mac.octets().into());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    // Build ARP packet
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(5);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr([0x00; 6].into());
    arp_packet.set_target_proto_addr(target_ip);

    // Combine Ethernet + ARP
    ethernet_packet.set_payload(arp_packet.packet());
    tx.send_to(ethernet_packet.packet(), None).unwrap();
    use pnet::packet::arp::ArpPacket;
    use pnet::packet::ethernet::EthernetPacket;

    let timeout = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while std::time::Instant::now() < timeout {
        if let Ok(packet) = rx.next() {
            if let Some(eth_packet) = EthernetPacket::new(packet) {
                if eth_packet.get_ethertype() == EtherTypes::Arp {
                    if let Some(reply) = ArpPacket::new(eth_packet.payload()) {
                        if reply.get_operation() == ArpOperations::Reply && reply.get_sender_proto_addr() == target_ip {
                            return Some((reply.get_sender_proto_addr(), format!("{:X?}", reply.get_sender_hw_addr())))
                        }
                    }
                }
            }
        }
    }
    None
}

/// Scan all IPs in the network useing ARP
async fn arp_scan(interface: &NetworkInterface) {
    let network = interface.ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .and_then(|ip| match ip {
            IpNetwork::V4(net) => Some(net.clone()),
            _ => None,
        }).expect("No IPv4 network found on the interface!");

    let base_ip = u32::from(network.ip());
    let mask = network.prefix();
    let start_ip = base_ip & !(0xffffffff >> mask);
    let end_ip = start_ip | (0xffffffff >> mask);

    // let mut detected_devices = HashSet::new();
    let mut tasks = vec![];

    for i in start_ip..end_ip {
        let ip = Ipv4Addr::from(i);
        let interface_clone = interface.clone();

        tasks.push(task::spawn(async move {
            if let Some((ip, mac)) = send_arp_request(&interface_clone, ip) {
                let device_name = get_device_name(IpAddr::V4(ip)).await;
                match device_name {
                    Some(name) => println!("✅ Device found: IP: {}, MAC: {}, Name: {}", ip, mac, name),
                    None => println!("✅ Device found: IP: {}, MAC: {}, Name: Unknown", ip, mac),
                }
                // detected_devices.insert(ip);
            }
        }));
    }
    
    // Await all tasks
    for task in tasks {
        let _ = task.await;
    }

}


/// Scan all IPs in a subnet
async fn scan_network(network: IpNetwork) {
    if let IpNetwork::V4(v4_net) = network {
        let base_ip = u32::from(v4_net.ip());
        let mask = v4_net.prefix();

        let start_ip = base_ip & !(0xffffffff >> mask);
        let end_ip = start_ip | (0xffffffff >> mask);

        let mut tasks = vec![];

        for i in start_ip..=end_ip {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(i));
            tasks.push(tokio::spawn(scan_ip(ip)));
        }

        for task in tasks {
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_get_network_interfaces() {
        let interfaces = get_network_interfaces();
        let interface = interfaces
            .into_iter()
            .find(|i| i.name == "en0")
            .expect("No active interfaces found");
        println!("Using interface {}", interface.name);
        arp_scan(&interface).await;
        // let networks = get_ip_networks(&interface);
        // println!("Scanning the following networks:");
        // for net in &networks {
            // println!("{}", net)
        // }

        // for network in networks {
            // scan_network(network).await;
        // }

    }
}