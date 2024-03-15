use tokio::sync::Mutex;
use tokio_native_tls::TlsStream;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::net::TcpListener;
use std::net::SocketAddr;
use uuid::Uuid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use crate::session;
use crate::config::AppConfig;

// Import Result type
use std::result::Result;

type Error = Box<dyn std::error::Error + Send + Sync>;

// Type alias for connection map
type ConnectionMap = HashMap<String, Arc<Mutex<TlsStream<tokio::net::TcpStream>>>>;

// Import error_handler and key modules
use super::{error_handler, key};

pub async fn run_server(config: AppConfig) {
    // Obtain the public key path from check_or_generate_tls_key
    let public_key_path = match key::check_or_generate_tls_key().await {
        Ok(path) => path,
        Err(e) => {
            error_handler::log_and_display_error("Error checking or generating TLS public key", &e);
            return;
        }
    };

    // Read the contents of the key file
    let public_key_contents = match key::read_tls_key_contents(&public_key_path).await {
        Ok(contents) => contents,
        Err(e) => {
            error_handler::log_and_display_error("Error reading TLS private key", &e);
            return;
        }
    };

    // Parse the private key and certificate from the contents
    let identity = match native_tls::Identity::from_pkcs12(&public_key_contents.into_bytes(), "") {
        Ok(identity) => identity,
        Err(e) => {
            error_handler::log_and_display_error("Error parsing TLS private key and certificate", &e);
            return;
        }
    };

    // (TLS initialization, listener creation, and connection HashMap creation)
    let addr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
    let listener = TcpListener::bind(&addr).await.unwrap();

    // TLS Key initialization
    let tls_key = match native_tls::TlsAcceptor::builder(identity).build() {
        Ok(tls_key) => tls_key,
        Err(e) => {
            error_handler::log_and_display_error("Error building TLS private key", &e);
            return;
        }
    };

    let tls_cx = tokio_native_tls::TlsAcceptor::from(tls_key);
    let connections: Arc<Mutex<ConnectionMap>> = Arc::new(Mutex::new(HashMap::new()));
    let session_cache = Arc::new(Mutex::new(session::SessionCache::new(config.clone())));

    loop {
        // Accept incoming TCP connections
        let (stream, _addr) = listener.accept().await.unwrap();

        // Perform TLS handshake
        let tls_stream = match tls_cx.accept(stream).await {
            Ok(tls_stream) => Arc::new(Mutex::new(tls_stream)),
            Err(e) => {
                // Handle TLS handshake error using the error handler
                error_handler::log_and_display_error("Error during Diffie-Hellman key exchange", &e);
                continue;
            }
        };

        // Perform x25519 Diffie-Hellman key exchange
        let (ephemeral_secret, ephemeral_public) = {
            let mut rng = ChaCha20Rng::from_seed(generate_secure_seed());
            let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
            let ephemeral_public = PublicKey::from(&ephemeral_secret); // <-- Derive public key before move
            (ephemeral_secret, ephemeral_public)
        };

        // Share public key with the other party
        let public_key_bytes = ephemeral_public.as_bytes().to_vec();
        let connections_clone = connections.clone();
        let session_cache_clone = session_cache.clone();

        tokio::spawn(async move {
            // Clone `tls_stream` before moving it into the closure
            let tls_stream_clone = tls_stream.clone();

            // Access and use the cloned tls_stream within the closure
            let mut tls_stream_mutex = tls_stream_clone.lock().await;
            tls_stream_mutex.write_all(&public_key_bytes).await.expect("Failed to send public key");

            let mut tls_stream = tls_stream_mutex; // Obtain a mutable reference

            // Diffie-Hellman key exchange and shared secret derivation
            let peer_public = match tls_stream.read_exact(&mut [0u8; 32]).await {
                Ok(n) => {
                    if n != 32 {
                        // Handle invalid key size
                        return;
                    }
                    let mut key_bytes = [0u8; 32];
                    tls_stream.read_exact(&mut key_bytes).await.expect("Failed to read peer public key");
                    PublicKey::from(key_bytes)
                }
                Err(e) => {
                    // Handle TLS handshake error using the error handler
                    error_handler::log_and_display_error("Error during Diffie-Hellman key exchange", &e);
                    return;
                }
            };

            let shared_secret = ephemeral_secret.diffie_hellman(&peer_public);
            let encryption_key = derive_encryption_key(&shared_secret).expect("Failed to derive encryption key");

            // Check if the Peer has a valid session token
            let mut session_token = [0u8; 32];
            match tls_stream.read_exact(&mut session_token).await {
                Ok(_) => {
                    let mut session_cache_lock = session_cache_clone.lock().await;
                    if let Some(encrypted_data) = session_cache_lock.retrieve_session_data(&session_token) {
                        // Session token found in cache, resume the session
                        let session_key = session_cache_lock.derive_session_key(shared_secret.as_bytes(), b"salt", b"info");
                        if let Some(decrypted_data) = session_cache_lock.decrypt_session_data(&encrypted_data, &session_key) {
                            // Process the decrypted session data and continue the session
                            // ...
                            return;
                        }
                    }
                }
                Err(_) => {
                    // Peer doesn't have a valid session token, proceed with new session
                    error_handler::log_and_display_error("Error Peer presented an invalid Session Token", &"Invalid session token");
                }
            }
            let session_token = session_cache_clone.lock().await.generate_session_token();
            let session_key = derive_encryption_key(&shared_secret).expect("Failed to derive encryption key");

            // Encrypt and store the session data in the cache
            let session_data = b"some_session_data";
            let encrypted_data = session_cache_clone.lock().await.encrypt_session_data(session_data, &session_key);
            session_cache_clone.lock().await.store_session_data(&session_token, &encrypted_data);

            // Send the session token to the client
            tls_stream.write_all(&session_token).await.expect("Failed to send session token");

            let connections_clone = connections_clone.clone();
            tokio::spawn(handle_connection(generate_connection_id(), connections_clone, encryption_key));
        });

        // Periodically remove expired sessions from the cache
        let session_cache_clone = session_cache.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                session_cache_clone.lock().await.remove_expired_sessions();
            }
        });
    }
}
fn generate_connection_id() -> String {
    Uuid::new_v4().to_string()
}
async fn handle_connection(
    connection_id: String,
    connections: Arc<Mutex<ConnectionMap>>,
    encryption_key_vec: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("WebSocket connection established for ID: {}", connection_id);

    // Retrieve the TLS stream from the connection map
    let tls_stream_mutex = {
        let connections_lock = connections.lock().await;
        connections_lock.get(&connection_id).unwrap().clone()
    };

    // Convert the Vec<u8> encryption key to a Key type
    let encryption_key = Key::from_slice(&encryption_key_vec).unwrap();

    let mut tls_stream = tls_stream_mutex.lock().await;

    // Read incoming data from the TLS stream
    let mut buf = [0u8; 1024];
    while let Ok(n) = tls_stream.read(&mut buf).await {
        if n == 0 {
            break;
        }

        // Generate a new nonce for each message
        let nonce_bytes = sodiumoxide::randombytes::randombytes(secretbox::NONCEBYTES);
        let nonce = Nonce::from_slice(&nonce_bytes).unwrap();

        // Decrypt the incoming data
        let plaintext = match decrypt(&buf[..n], &encryption_key, &nonce) {
            Some(plaintext) => plaintext,
            None => {
                // Handle decryption failure
                error_handler::log_and_display_error("Decryption error", &"Decryption failed");
                continue;
            }
        };

        // Process the decrypted plaintext message
        println!("Received message: {:?}", plaintext);

        // Encrypt a response message
        let response = b"Hello, client!";
        let ciphertext = encrypt(response, &encryption_key, &nonce);

        // Send the encrypted response back to the client
        tls_stream.write_all(&ciphertext).await.expect("Failed to send response");
    }

    // Remove the connection from the map when done
    connections.lock().await.remove(&connection_id);

    Ok(())
}
fn derive_encryption_key(shared_secret: &SharedSecret) -> Result<Vec<u8>, hkdf::InvalidLength> {
    let salt = sodiumoxide::randombytes::randombytes(32); // Generate random salt
    let info = b"encryption_key";

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());  // Correct arguments for Hkdf::new
    let mut key_material = vec![0u8; 32]; // Create a mutable buffer for key material

    hkdf.expand(info, &mut key_material)?; // Use mutable reference and handle Result

    Ok(key_material) // Return the derived key material
}

fn encrypt(message: &[u8], key: &Key, nonce: &Nonce) -> Vec<u8> {
    let ciphertext = secretbox::seal(message, nonce, key);
    let mut pmc_ciphertext = Vec::new();
    pmc_ciphertext.extend_from_slice(&ciphertext[0..16]); // PMC header
    pmc_ciphertext.extend_from_slice(&ciphertext[24..]); // PMC encrypted message
    pmc_ciphertext
}

fn decrypt(ciphertext: &[u8], key: &Key, nonce: &Nonce) -> Option<Vec<u8>> {
    let mut full_ciphertext = Vec::with_capacity(ciphertext.len() + 16);
    full_ciphertext.extend_from_slice(&ciphertext[0..16]); // PMC header
    full_ciphertext.extend_from_slice(&[0u8; 8]); // PMC placeholder
    full_ciphertext.extend_from_slice(&ciphertext[16..]); // PMC encrypted message

    secretbox::open(&full_ciphertext, nonce, key).ok()
}

fn generate_secure_seed() -> [u8; 32] {
    // Generate a secure random seed for the CSPRNG
    let mut seed = [0u8; 32];
    // Use a secure source of randomness to fill the seed, e.g., OsRng
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}