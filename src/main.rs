// use dns-lookup; // TODO fix the import
use std::thread;
use crate::node::Node;
use crate::tcp_socket::Tcp_socket;
mod node;
mod tcp_socket;

fn main() {
    let test_node = Node::new();
    let server_thread = thread::spawn(move || {
        node::server_thread_create();
    });
    test_node.send_message("hello from client1".to_string());
    test_node.send_message("hello from client2".to_string());
    test_node.send_message("hello from client3".to_string());
    test_node.send_message("hello from client4".to_string());
    test_node.send_message("hello from client5".to_string());
    test_node.send_message("hello from client6".to_string());
    let server_res = server_thread.join();
}

