use std::collections::HashMap;
use std::net::TcpStream;
use dns_lookup::{get_hostname, lookup_host};
use std::net::IpAddr;
use crate::tcp_socket::Tcp_socket;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, TryRecvError};
use std::{thread, time};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme};
use rand::rngs::OsRng;
use rand_core::{RngCore, Error, impls};
// use Nemocracy::key::gen_keypair;
use fujisaki_ringsig::{gen_keypair, sign, verify, Tag};



const MSG_SIZE:usize = 256;
const INTRODUCER_IP: &str = "192.168.1.133"; // 192.168.31.154 for local test, 172.22.94.218 for vm test
const PORT: &str = ":6000";

pub struct Node {
    id: String, // also used a public key
    hb:i32, 
    local_clock:i32,
    membership_list: HashMap <String, (i32, i32, u8)>, // ID -> (hb, clock, flag) *flag -> honest, crash, byzantine
    status: u8, // INACTIVE = 0, ACTIVE = 1
    tcp_util: Tcp_socket,
    secret_key: fujisaki_ringsig::PrivateKey,
    public_key: fujisaki_ringsig::PublicKey,
    ssk: RSAPrivateKey,
    spk: RSAPublicKey,
    trs: (u64, Vec<String>, u64)


}

impl Node {
    pub fn new() -> Node{
        println!("creating new node");
        let mut rng = OsRng;
        let mut rng1 = OsRng;
        println!("rng: {:?} \n rng1{:?}", rng, rng1);
        let bits = 2048;
        // let rsa_secret= RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        // let rsa_public = RSAPublicKey::from(&rsa_secret);
        let (sk, pk) = fujisaki_ringsig::gen_keypair(rng);
        let rsa_ssk= RSAPrivateKey::new(&mut rng1, bits).expect("failed to generate a key");
        let rsa_spk = RSAPublicKey::from(&rsa_ssk); 
        // println!("secret key: {:?}, public key: {:?}", rsa_secret, rsa_public);
        Node {
            id: Node::create_id(),
            hb: 0,
            local_clock: 0,
            status: 0,
            tcp_util: Tcp_socket::new(),
            membership_list: HashMap::new(),
            secret_key: sk,
            public_key: pk,
            ssk: rsa_ssk,
            spk: rsa_spk,
            trs: (0, vec![], 0)
        }
        

    }

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    pub fn start_honest(mut self) {
        // Hardcode membership list for now
        
            println!("starting honest node");

            // 1. join the system by sending public_key to the introducer

            // 3. create traceable ring signature (Trs = <ski, L, m>, L = tag(issue, {pki}N), m = spki
            //     {pki}N is the set of all public keys
            // let mut all_public_keys = vec!["node0".to_string(), "node1".to_string(), "node2".to_string(), "node3".to_string(), "node4".to_string(), "node5".to_string(), "node6".to_string(), "node7".to_string(), "node8".to_string(), "node9".to_string()];
            let mut msg: String = String::new();
            msg.push_str("[0]::");
            let mut public_key_vec = self.public_key.as_bytes();
            println!("public_key_vec: {:?}", public_key_vec);

            let public_str = String::from_utf8_lossy(&mut public_key_vec);
            msg.push_str(&public_str);
            // msg.push_str(self.public_key.as_bytes().to_owned());
            println!("sending to {}, msg: {}", INTRODUCER_IP.to_string(), msg);
            self.send_message(INTRODUCER_IP.to_string(), msg);
            // println!("trs keypair: {:?}", (self.secret_key, self.public_key));
            // let mut rng = rand::thread_rng();
            // let (_, pk2) = gen_keypair(&mut rng);
            // let (_, pk3) = gen_keypair(&mut rng);
            // let (_, pk4) = gen_keypair(&mut rng);
            // let (_, pk5) = gen_keypair(&mut rng);
            // let (_, pk6) = gen_keypair(&mut rng);
            // let (_, pk7) = gen_keypair(&mut rng);
            // let (_, pk8) = gen_keypair(&mut rng);
            // let (_, pk9) = gen_keypair(&mut rng);
            // let (_, pk10) = gen_keypair(&mut rng);

            // let all_pks = vec![self.public_key, pk2, pk3, pk4, pk5, pk6, pk7, pk8, pk9, pk10];
            
            // let issue = b"anonymous pki".to_vec();

            // let tag = fujisaki_ringsig::Tag {issue, all_pks};



            // self.trs = (self.secret_key.clone(),all_public_keys, self.spk.clone());
            // println!("trs: {:?}", self.trs); //worked

            //TODO use the traceable signature scheme


            // 4. send (spki, trsi) to all (sign using ski)
            //     each party also receive from others, by the end it gets a set 
            //     sspksi = {(spki, trsi)} (i = 0-n) (Signed Shadowed public key set at i)
            // 5. Send sspksi to all others (dolev strong)
            // 6. take the union of all received sets (sspksu)(Signed Shadowed public key set union)
            // 7. run va = ver(spka, trsa) (using pka to verify the authenticity) for all pair and remove parties (spka, trsa) whose va != 1
            // 8. t_ab = trace(L, (spka, trsa), (spkb, trsb)) for all pairs in the union and remove sspka and sspkb for those t_ab != "indep" and spka != spkb.
            //     After this step we get a master signed shadow public key set msspks
            // 9. output anonymout PKI{spki | (spki, trsi) is party of msspks} 

            
            


    }

    pub fn send_message(&self, target: String, msg: String) {
        thread::sleep(time::Duration::from_millis(2000));
        // println!("client send message");
        // let host_name = dns_lookup::get_hostname().unwrap();
        // let ip_addr: Vec<IpAddr> = lookup_host(&host_name).unwrap();
        let mut connect_param = target.clone();
        connect_param.push_str(PORT);
        println!("target: {}, msg: {}", connect_param, msg);
        let mut target = TcpStream::connect(connect_param).expect("client Stream failed to connect");
        target.set_nonblocking(true).expect("client failed to initialize non-blocking");

        let(tx, rx) = mpsc::channel::<String>();

        thread::spawn(move || loop{
            let mut buff = vec![0; MSG_SIZE];
            // match target.read_exact(&mut buff) {
            //     Ok(_) => {
            //         // println!("read exact buf: {:?}", buff);
            //         let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
            //         println!("message recv {:?}", msg);
            //     }, 
            //     Err (ref err) if err.kind() == ErrorKind::WouldBlock => (),
            //     Err(_) => {
            //         println!("connection with server was severed");
            //         break;
            //     }
            // }
            // TODO process received message
            match rx.try_recv() {
                Ok(msg)=> {
                    let mut buff = msg.clone().into_bytes();
                    buff.resize(MSG_SIZE, 0);
                    target.write_all(&buff).expect("client writing to socket failed");
                    println!("message sent {:?}", msg);
                }, 
                Err(TryRecvError::Empty) => (),
                Err(TryRecvError::Disconnected) => break
            }
            thread::sleep(time::Duration::from_millis(1000));

        });

        println!("Sending message...:{}", msg);
        // tx.send(msg);
        // tx.send("1111111111".to_string());
        loop {
            // tx.send("1111111111".to_string());
            tx.send(msg.clone());
            thread::sleep(time::Duration::from_millis(2000));
        }
    }

    pub fn honest() {
        
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

            // let tx = tx.clone();

            clients.push(socket.try_clone().expect("failed to clone client"));

            thread::spawn(move || loop {
                let mut buff = vec![0; MSG_SIZE]; // MSG_SIZE 0s
                // let mut buff = vec![];
                match socket.read_exact(&mut buff) {
                    Ok(_) => {
                        let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                        let msg = String::from_utf8(msg).expect("Invalid utf8 message");

                        println!("server receive {}, {:?}", addr, msg);
                        //TODO process message here
                        
                        // tx.send(msg).expect("failed to send msg to rx");
                    },

                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                    Err(e) => {
                        println!("closing connection with :{}, Err:{:?}", addr, e);
                        break;
                    }
                }

                std::thread::sleep(sleep_period);
            });
        }

        // if let Ok(msg) = rx.try_recv() {
        //     clients = clients.into_iter().filter_map(|mut client| {
        //         let mut buff = msg.clone().into_bytes();
        //         buff.resize(MSG_SIZE, 0);

        //         client.write_all(&buff).map(|_| client).ok()
        //     }).collect::<Vec<_>>();
        // }
        std::thread::sleep(sleep_period);
    }
}