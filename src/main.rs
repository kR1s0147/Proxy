extern crate pnet;
use pnet::datalink::{self, Channel};
use pnet::packet::{Packet, ethernet::EthernetPacket, tcp::TcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncReadExt,AsyncWriteExt};
use tokio::net::{TcpListener,TcpStream};
use tokio::spawn;
use std::error::Error;
use std::time::{Duration,Instant};
use dashmap::DashMap;
use std::sync::Arc;
use std::process::Command;
use tokio::sync::mpsc;
use std::sync::Mutex;
use futures_util::StreamExt; 


const SYN_THRESHOLD: usize = 50; // Threshold for SYN packets
const TIME_WINDOW: Duration = Duration::from_secs(120); // Time window for SYN flood detection

fn is_external_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    (octets[0] == 10 ||                                  // 10.x.x.x
      (octets[0] == 172 && (16..=31).contains(&octets[1])) || // 172.16.x.x - 172.31.x.x
      (octets[0] == 192 && octets[1] == 168) ||            // 192.168.x.x
      ip.is_loopback())                                    // 127.x.x.x
}

#[tokio::main]
async fn main() -> Result<(),Box<dyn Error>>{

    let listener= TcpListener::bind("192.168.147.76:5001").await.unwrap();

    println!("server running on 5001");

    // Get available network interfaces and filter for wlp2s0
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == "wlp2s0")
        .expect("Error: Could not find interface wlp2s0");

        let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()).unwrap() {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => panic!("Unsupported channel type"),
        };
    
        // Create the mpsc channel
        let (tx, mut rx_channel) = mpsc::channel(100); 
    // Create a channel to capture packets on wlp2s0
    tokio::task::spawn(async move {
        // Wrap rx in Arc and Mutex to share across threads
        let re = Arc::new(Mutex::new(rx));
        loop {
            let rx1 = Arc::clone(&re);
            let packet_option = {
                // Lock the mutex and extract the packet while lock is held
                let mut guard = rx1.lock().unwrap();
                guard.next().map(|packet| packet.to_vec())// This releases the lock as soon as guard is dropped
            };
             
             // Clone the Arc once per iteration // Lock the Mutex
            match packet_option {
                Ok(packet) => {
                    // Handle the result of tx.send() asynchronously
                    if let Err(e) = tx.send(packet).await {
                        eprintln!("Failed to send packet: {}", e);
                    }
                },
                Err(e) => {
                    eprintln!("No more packets available.");
                    break;
                }
            }
        }
    });

    let syn_count: Arc<Mutex<HashMap<Ipv4Addr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let last_time: Arc<Mutex<_>> = Arc::new(Mutex::new(Instant::now())); 
 

    loop{
        tokio::select!{
            Ok((stream, _)) = listener.accept() => {
                println!("new connection :{:?}",stream);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
                        eprintln!("Error handling connection: {}", e);
                    }
                });
            }

           packet=rx_channel.recv() => {
                    match packet {
                        Some(packet) => {
                            let syn_count_clone = Arc::clone(&syn_count);  // Clone the Arc for syn_count
                            let last_time_clone = Arc::clone(&last_time); 
                            tokio::spawn(async move {
                                capture_packet(packet.as_slice(), syn_count_clone, last_time_clone).await;
                            });
                        }
                        None=>{
                            println!("None recived");
                        }
                        
                }
        }
        }
    }
        Ok(())
}


async fn capture_packet(packet: &[u8],syn_counts:Arc<Mutex<HashMap<Ipv4Addr, usize>>>,mut last_time:Arc<Mutex<Instant>>){
    let eth_packet = EthernetPacket::new(packet).unwrap();
                
    // Filter IPv4 packets
    if eth_packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
        let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();

        // Check if it's TCP traffic
        if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
            let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
            
            let source_ip = IpAddr::V4(ipv4_packet.get_source());
            let destination_ip = IpAddr::V4(ipv4_packet.get_destination());

            let source_port = tcp_packet.get_source();
            let destination_port = tcp_packet.get_destination();
            // Check for SYN flag in the TCP header
            if tcp_packet.get_flags() & 0x02 != 0 {
                let source_ip = ipv4_packet.get_source();
                
                // Only process external IPs
                if is_external_ip(source_ip) {
                    println!("{:?}",source_ip);
                    let mut syn_count= syn_counts.lock().unwrap();
                    let mut last_time=last_time.lock().unwrap();
                    *syn_count.entry(source_ip).or_insert(0) += 1;

                    if last_time.elapsed() > TIME_WINDOW {
                        syn_count.clear();
                        *last_time = Instant::now();
                    }

                    if syn_count[&source_ip] > SYN_THRESHOLD {
                        spawn(async move{
                            block_ip(&source_ip).await;
                        });
                    } else {
                        println!("SYN packet detected from {}", source_ip);
                    }
            }
            }
            // if tcp_packet.get_flags() & 0x10 != 0 {
            //     // Pass established connections to another function
            //     spawn(async move {
            //                 if let Err(e)=handle_connection(source_ip,source_port).await{
            //                     println!("Cant handle connection");
            //                 }
            //             });
            // }
        }
    }
}
// Function to block an IP address using iptables
async fn block_ip(ip: &Ipv4Addr) {
    let ip_str = ip.to_string();

    if ip_str == "192.168.43.76"{
        return ;
    }
    let output = Command::new("sudo")
        .arg("iptables")
        .arg("-A")     // Append a new rule
        .arg("INPUT")  // In the INPUT chain (for incoming traffic)
        .arg("-s")     // Source address
        .arg(&ip_str)  // The IP address to block
        .arg("-j")     // Jump to target
        .arg("DROP")   // Drop the packets
        .output()      // Run the command
        .expect("Failed to execute iptables command");

    if output.status.success() {
        println!("Successfully blocked IP: {}", ip_str);
    } else {
        eprintln!("Failed to block IP: {}", ip_str);
        eprintln!("Error: {:?}", String::from_utf8_lossy(&output.stderr));
    }
}

async fn handle_connection(mut inbound:TcpStream) -> Result<(),Box<dyn Error>>{
   


    let target="192.168.147.76:80";

    let mut outbound= TcpStream::connect(target).await?;

    let (mut inboundReader, mut inboundWriter)=inbound.split();

    let (mut outboundReader, mut outboundWriter)=outbound.split();



    let client_to_sever = async {
        tokio::io::copy(& mut inboundReader,& mut outboundWriter).await?;
        outboundWriter.shutdown().await
    };

    let server_to_client= async {
        tokio::io::copy(& mut outboundReader,& mut inboundWriter).await?;
        inboundWriter.shutdown().await
    };

    tokio::try_join!(client_to_sever,server_to_client)?;

    Ok(())
}
