use std::collections::HashMap;
use std::net::TcpStream;
use dns_lookup::{get_hostname, lookup_host};
use std::net::IpAddr;
use crate::tcp_socket::Tcp_socket;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, TryRecvError};
use std::{thread, time};


const MSG_SIZE:usize = 256;

pub struct Node {
    id: String,
    hb: i32, 
    local_clock: i32,
    membership_list: HashMap <String, (i32, i32, u8)>, // ID -> (hb, clock, flag) *flag -> honest, crash, byzantine
    status: u8, // INACTIVE = 0, ACTIVE = 1
    tcp_util: Tcp_socket
    //TODO: UDP socket


}

impl Node {
    pub fn new() -> Node{
        println!("creating new node");
       
        Node {
            id: Node::create_id(),
            hb: 0,
            local_clock: 0,
            status: 0,
            tcp_util: Tcp_socket::new(),
            membership_list: HashMap::new()
        }
        

    }

    pub fn send_message(&self, msg: String) {
        thread::sleep(time::Duration::from_millis(2000));
        println!("client send message");
        let host_name = dns_lookup::get_hostname().unwrap();
        let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
        let mut connect_param = ip_addr[0].to_string();
        connect_param.push_str(":6000");
        println!("connect_param: {}", connect_param);
        let mut client = TcpStream::connect(connect_param).expect("client Stream failed to connect");
        client.set_nonblocking(true).expect("client failed to initialize non-blocking");

        let(tx, rx) = mpsc::channel::<String>();

        thread::spawn(move || loop{
            let mut buff = vec![0; MSG_SIZE];
            match client.read_exact(&mut buff) {
                Ok(_) => {
                    let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                    println!("message recv {:?}", msg);
                }, 
                Err (ref err) if err.kind() == ErrorKind::WouldBlock => (),
                Err(_) => {
                    println!("connection with server was severed");
                    break;
                }
            }

            match rx.try_recv() {
                Ok(msg)=> {
                    let mut buff = msg.clone().into_bytes();
                    buff.resize(MSG_SIZE, 0);
                    client.write_all(&buff).expect("client writing to socket failed");
                    println!("message sent {:?}", msg);
                }, 
                Err(TryRecvError::Empty) => (),
                Err(TryRecvError::Disconnected) => break
            }
            thread::sleep(time::Duration::from_millis(1000));

        });

        println!("Write a Message!");
        tx.send(msg);
        // loop {
        //     tx.send(msg);
        // }
    }



    fn create_id() -> String {
        let host_name = dns_lookup::get_hostname().unwrap();
        println!("hostname: {:?}", host_name);
        
        let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
        println!("ip_addr: {:?}", ip_addr);

        ip_addr[0].to_string()
    }
}

pub fn server_thread_create() {
    println!("server_thread_create");
    let host_name = dns_lookup::get_hostname().unwrap();
    let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
    let mut bind_param = ip_addr[0].to_string();
    bind_param.push_str(":6000");
    println!("full address: {}", bind_param);

    let server = TcpListener::bind(bind_param).expect("Listener failed to bind");
    server.set_nonblocking(true).expect("failed to initialize non-blocking");

    let mut clients = vec![]; // vector os connected clients

    let (tx, rx) = mpsc::channel::<String>();
    let sleep_period = time::Duration::from_millis(1000);
    loop {
        println!("server receive loop");
        if let Ok((mut socket, addr)) = server.accept() {
            println!("Client {} connected", addr);

            let tx = tx.clone();

            clients.push(socket.try_clone().expect("failed to clone client"));

            thread::spawn(move || loop {
                let mut buff = vec![0; MSG_SIZE]; // MSG_SIZE 0s

                match socket.read_exact(&mut buff) {
                    Ok(_) => {
                        let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                        let msg = String::from_utf8(msg).expect("Invalid utf8 message");

                        println!("{}, {:?}", addr, msg);

                        tx.send(msg).expect("failed to send msg to rx");
                    },

                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                    Err(_) => {
                        println!("closing connection with :{}", addr);
                        break;
                    }
                }

                std::thread::sleep(sleep_period);
            });
        }

        if let Ok(msg) = rx.try_recv() {
            clients = clients.into_iter().filter_map(|mut client| {
                let mut buff = msg.clone().into_bytes();
                buff.resize(MSG_SIZE, 0);

                client.write_all(&buff).map(|_| client).ok()
            }).collect::<Vec<_>>();
        }
        std::thread::sleep(sleep_period);
    }
}