mod node;
mod error_handler;
mod key;
mod session;
mod config;
mod zk_proof;

#[tokio::main]
async fn main() {
    // Initialize logging
    error_handler::initialize_logger();

    // Load configuration
    let config = config::AppConfig::new();

    // Run the server from the node module
    node::run_server(config).await;
}