use crate::config::AppConfig;
use crate::encryption;
use crate::error_handler;
use crate::zk_proof::generate_token_ownership_proof;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Key, Nonce};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector;
use x25519_dalek::PublicKey;

const MAX_RECONNECT_ATTEMPTS: usize = 5;
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

pub async fn connect_to_node(
    config: AppConfig,
    target_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reconnect_attempts = 0;

    loop {
        let mut tls_stream = match establish_tls_connection(&target_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error_handler::log_and_display_error("Failed to establish TLS connection", &e);
                reconnect_attempts += 1;
                if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                    return Err("Max reconnect attempts reached".into());
                }
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        let (shared_secret, encryption_key) = match perform_key_exchange(&mut tls_stream).await {
            Ok(result) => result,
            Err(e) => {
                error_handler::log_and_display_error("Failed to perform key exchange", &e);
                reconnect_attempts += 1;
                if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                    return Err("Max reconnect attempts reached".into());
                }
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        let session_token = match get_or_receive_session_token(&mut tls_stream).await {
            Ok(token) => token,
            Err(e) => {
                error_handler::log_and_display_error("Failed to get or receive session token", &e);
                reconnect_attempts += 1;
                if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                    return Err("Max reconnect attempts reached".into());
                }
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        if let Err(e) = send_proof_and_verifying_key(&mut tls_stream, &session_token).await {
            error_handler::log_and_display_error("Failed to send proof and verifying key", &e);
            reconnect_attempts += 1;
            if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                return Err("Max reconnect attempts reached".into());
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        }

        let session_token_array: [u8; 32] = session_token.try_into().unwrap();

        if let Err(e) = handle_connection(&mut tls_stream, &encryption_key, &session_token_array).await {
            error_handler::log_and_display_error("Connection error", &e);
            reconnect_attempts += 1;
            if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                return Err("Max reconnect attempts reached".into());
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        } else {
            break;
        }
    }

    Ok(())
}

async fn establish_tls_connection(
    target_addr: &SocketAddr,
) -> Result<tokio_native_tls::TlsStream<tokio::net::TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let stream = TcpStream::connect(target_addr).await?;
    let tls_connector = TlsConnector::from(native_tls::TlsConnector::new()?);
    let tls_stream = tls_connector.connect("localhost", stream).await?;
    Ok(tls_stream)
}

async fn perform_key_exchange(
    tls_stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
) -> Result<(x25519_dalek::SharedSecret, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let (ephemeral_secret, ephemeral_public) = encryption::generate_key_pair();
    let public_key_bytes = ephemeral_public.as_bytes().to_vec();
    tls_stream.write_all(&public_key_bytes).await?;

    let mut peer_public_bytes = [0u8; 32];
    tls_stream.read_exact(&mut peer_public_bytes).await?;
    let peer_public = PublicKey::from(peer_public_bytes);

    let shared_secret = ephemeral_secret.diffie_hellman(&peer_public);
    let encryption_key = encryption::derive_encryption_key(&shared_secret)
        .map_err(|e| format!("Failed to derive encryption key: {}", e))?;

    Ok((shared_secret, encryption_key))
}

async fn get_or_receive_session_token(
    tls_stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let session_token_path = Path::new("session_token.bin");
    if session_token_path.exists() {
        let session_token = fs::read(session_token_path)?;
        Ok(session_token)
    } else {
        let mut session_token = [0u8; 32];
        tls_stream.read_exact(&mut session_token).await?;
        Ok(session_token.to_vec())
    }
}

async fn send_proof_and_verifying_key(
    tls_stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
    session_token: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (proof_vec, verifying_key_vec) = generate_token_ownership_proof(session_token)
        .map_err(|e| format!("Failed to generate token ownership proof: {}", e))?;

    tls_stream.write_all(&proof_vec).await?;
    tls_stream.write_all(&verifying_key_vec).await?;

    Ok(())
}

async fn handle_connection(
    tls_stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
    encryption_key: &[u8],
    session_token: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encryption_key = Key::from_slice(encryption_key).unwrap();
    fs::write("session_token.bin", session_token)?;

    let mut buf = [0u8; 1024];
    loop {
        let n = match tls_stream.read(&mut buf).await {
            Ok(n) if n == 0 => break,
            Ok(n) => n,
            Err(e) => {
                error_handler::log_and_display_error("Error reading from TLS stream", &e);
                return Err(e.into());
            }
        };

        let nonce_bytes = sodiumoxide::randombytes::randombytes(secretbox::NONCEBYTES);
        let nonce = Nonce::from_slice(&nonce_bytes).unwrap();

        let plaintext = match encryption::decrypt(&buf[..n], &encryption_key, &nonce) {
            Some(plaintext) => plaintext,
            None => {
                error_handler::log_and_display_error("Decryption error", &"Decryption failed");
                continue;
            }
        };

        println!("Received message: {:?}", plaintext);

        let response = b"Hello, node!";
        let ciphertext = encryption::encrypt(response, &encryption_key, &nonce);

        if let Err(e) = tls_stream.write_all(&ciphertext).await {
            error_handler::log_and_display_error("Error sending response", &e);
            return Err(e.into());
        }
    }

    Ok(())
}