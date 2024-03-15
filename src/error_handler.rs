// error_handler.rs

use log::{error, info};
use env_logger::{Builder, Env};

pub fn initialize_logger() {
    // Create the log directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all("log") {
        eprintln!("Error creating log directory: {:?}", e);
    }

    // Set up the logger with readable log level and redirect to a file
    Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .format_module_path(false)
        .format_level(true)
        .format_indent(Some(2))
        .write_style(env_logger::WriteStyle::Always)
        .init();
}

pub fn log_and_display_error(message: &str, error: &dyn std::fmt::Debug) {
    // Log the error
    error!("Error: {}: {:?}", message, error);
    info!("{}", message);
    // Display the error to the user or handle it as needed
    // Here, we simply print it to the console
    eprintln!("Error: {}: {:?}", message, error);
}
