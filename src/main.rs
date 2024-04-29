mod node;
mod error_handler;
mod key;
mod session;
mod config;
mod zk_proof;
mod encryption;
mod client;
mod gui;

use config::AppConfig;
#[tokio::main]
async fn main() {
    // Initialize logging
    // Initialize logging
    error_handler::initialize_logger();

    // Load configuration
    let config = AppConfig::new();

    // Run the GUI
    gui::run_gui(config);
}