// use dns-lookup; // TODO fix the import
use std::thread;
use std::io::{self, ErrorKind, Read, Write};
use crate::node::Node;
use crate::tcp_socket::Tcp_socket;
mod node;
mod tcp_socket;
use fujisaki_ringsig::{gen_keypair, sign, verify, Tag};
use std::sync::mpsc::{self, TryRecvError};
// use std::backtrace::Backtrace;
// mod key;
// mod lib;
// mod prelude;
// mod sig;
// mod test_utils;
// mod trace;
//0: new node joining
// const channel = mpsc::channel::<String>();

fn main() {
    // let bt = Backtrace::new();
    
    let(tx, rx) = mpsc::channel();
    println!("rx address in main: {:p}", &rx);
    println!("tx address in main: {:p}", &tx);
    let mut test_node = Node::new(rx);
    let server_thread = thread::spawn(move || {
        node::server_thread_create(tx);
        // &test_node.server_thread_create();
    });
    //TODO move server thread to the node struct


    println!("Please enter a role: H (honest) / B (Byzantine)");
    let mut buff = String::new();
    io::stdin().read_line(&mut buff).expect("reading from stdin failed");
    println!("buff: [{}]", buff);
    if buff == "H\n".to_string(){
        test_node.start_honest();
    }
    // test_node.start_honest();

    
    // test_node.send_message("hello from client1".to_string());
    // test_node.send_message("hello from client2".to_string());
    // test_node.send_message("hello from client3".to_string());
    // test_node.send_message("hello from client4".to_string());
    // test_node.send_message("hello from client5".to_string());
    // test_node.send_message("hello from client6".to_string());
    let server_res = server_thread.join();
    // println!("{:?}", bt);
}

