use config::{Config, FileFormat};
use std::time::Duration;
use serde::{Serialize, Deserialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(with = "serde_duration")]
    pub session_lifetime: Duration,
    pub listen_address: String,
    pub listen_port: u16,
    pub max_reconnect_attempts: usize,
    #[serde(with = "serde_duration")]
    pub reconnect_delay: Duration,
}
impl AppConfig {
    pub fn new() -> Self {
        let builder = Config::builder();

        // Check if config.ini exists, if not, create it with a prepopulated value
        if !fs::metadata("config.ini").is_ok() {
            let default_config = r#"
                [default]
                session_lifetime_seconds = 3600
                listen_address = "127.0.0.1"
                listen_port = 8080
                max_reconnect_attempts = 5
                reconnect_delay_seconds = 5
            "#;
            fs::write("config.ini", default_config).expect("Failed to create config.ini");
        }

        let conf = builder
            .add_source(config::File::new("config.ini", FileFormat::Ini))
            .build()
            .expect("Failed to build configuration");

        let session_lifetime_seconds = conf.get_int("default.session_lifetime_seconds")
            .expect("Failed to get session_lifetime_seconds") as u64;
        let listen_address = conf.get_string("default.listen_address")
            .expect("Failed to get listen_address");
        let listen_port = conf.get_int("default.listen_port")
            .expect("Failed to get listen_port") as u16;
        let max_reconnect_attempts = conf.get_int("default.max_reconnect_attempts")
            .expect("Failed to get max_reconnect_attempts") as usize;
        let reconnect_delay_seconds = conf.get_int("default.reconnect_delay_seconds")
            .expect("Failed to get reconnect_delay_seconds") as u64;

        AppConfig {
            session_lifetime: Duration::from_secs(session_lifetime_seconds),
            listen_address,
            listen_port,
            max_reconnect_attempts,
            reconnect_delay: Duration::from_secs(reconnect_delay_seconds),
        }
    }
}

mod serde_duration {
    use std::time::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
        where
            D: Deserializer<'de>,
    {
        let seconds = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(seconds))
    }
}