use std::collections::HashMap;
use std::net::UdpSocket;
use dns_lookup::{get_hostname, lookup_host};
use std::net::IpAddr;


pub struct Node {
    id: String,
    hb: i32, 
    local_clock: i32,
    membership_list: HashMap <String, (i32, i32, u8)>, // ID -> (hb, clock, flag) *flag -> honest, crash, byzantine
    status: u8,
    udp_util: UdpSocket,
    //TODO: UDP socket


}

impl Node {
    pub fn new() {
        println!("creating new node");
        let host_name = dns_lookup::get_hostname().unwrap();
        println!("hostname: {:?}", host_name);
        
        let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
        println!("ip_addr: {:?}", ip_addr);
    }

    // fn create_id() {

    // }
}