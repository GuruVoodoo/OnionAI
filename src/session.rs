use rand::Rng;
use sha3::{Sha3_256, Digest};
use aead::{Aead, KeyInit, generic_array::GenericArray};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use std::collections::HashMap;
use std::time::{SystemTime};
use std::fs::{File, OpenOptions};
use serde::{Serialize, Deserialize};
use crate::config::AppConfig;

// Define the session cache
#[derive(Serialize, Deserialize)]
pub struct SessionCache {
    cache: HashMap<Vec<u8>, (Vec<u8>, SystemTime)>,
    config: AppConfig,
}
impl SessionCache {
    pub fn new(config: AppConfig) -> Self {
        // Load the session cache from disk or create a new one
        match File::open("session_cache.bin") {
            Ok(file) => bincode::deserialize_from(file).unwrap_or_else(|_| SessionCache {
                cache: HashMap::new(),
                config,
            }),
            Err(_) => SessionCache {
                cache: HashMap::new(),
                config,
            },
        }
    }
    pub fn save_to_disk(&self) {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open("session_cache.bin")
            .expect("Failed to open session cache file");
        bincode::serialize_into(file, &self)
            .expect("Failed to save session cache to disk");
    }

    // Generate a unique session token
    pub fn generate_session_token(&self) -> Vec<u8> {
        let mut rng = rand::rngs::OsRng;
        let token: [u8; 32] = rng.gen();
        token.to_vec()
    }

    // Derive a session key from the shared secret
    pub fn derive_session_key(&self, shared_secret: &[u8], salt: &[u8], info: &[u8]) -> Vec<u8> {
        let hk = Hkdf::<Sha3_256>::new(Some(salt), shared_secret);
        let mut session_key = vec![0u8; 32];
        hk.expand(info, &mut session_key)
            .expect("Failed to derive session key");
        session_key
    }

    // Encrypt session data using AES-256-GCM
    pub fn encrypt_session_data(&self, session_data: &[u8], session_key: &[u8]) -> Vec<u8> {
        let key = GenericArray::from_slice(session_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(b"unique_nonce_12345"); // Use a unique nonce for each encryption
        cipher.encrypt(nonce, session_data)
            .expect("Failed to encrypt session data")
    }

    // Encrypt session data using AES-256-GCM
    pub fn decrypt_session_data(&self, encrypted_data: &[u8], session_key: &[u8]) -> Option<Vec<u8>> {
        let key = GenericArray::from_slice(session_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        cipher.decrypt(nonce, ciphertext).ok()
    }

    // Store encrypted session data in the cache
    pub fn store_session_data(&mut self, session_token: &[u8], encrypted_data: &[u8]) {
        let cache_key = self.generate_cache_key(session_token);
        let expiration = SystemTime::now() + self.config.session_lifetime;
        self.cache.insert(cache_key, (encrypted_data.to_vec(), expiration));
        self.save_to_disk();
    }

    // Retrieve session data from the cache
    pub fn retrieve_session_data(&mut self, session_token: &[u8]) -> Option<Vec<u8>> {
        let cache_key = self.generate_cache_key(session_token);
        let result = self.cache.entry(cache_key).and_modify(|(data, expiration)| {
            if SystemTime::now() >= *expiration {
                *data = Vec::new();
            }
        }).or_insert((Vec::new(), SystemTime::now())).0.clone();
        self.save_to_disk();
        Some(result)
    }

    // Generate a cache key using SHA3-256
    pub fn generate_cache_key(&self, session_token: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(session_token);
        hasher.finalize().to_vec()
    }

    // Remove expired session data from the cache
    pub fn remove_expired_sessions(&mut self) {
        self.cache.retain(|_, (_, expiration)| SystemTime::now() < *expiration);
        self.save_to_disk();
    }
}