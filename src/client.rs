use crate::config::AppConfig;
use crate::encryption;
use crate::error_handler;
use crate::zk_proof::{generate_token_ownership_proof,generate_tls_certificate_proof, verify_tls_certificate_proof, generate_pfs_public_key_proof, verify_pfs_public_key_proof};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Key, Nonce};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector;
use x25519_dalek::PublicKey;

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
                if reconnect_attempts >= config.max_reconnect_attempts {
                    return Err("Max reconnect attempts reached".into());
                }
                tokio::time::sleep(config.reconnect_delay).await;
                continue;
            }
        };

        let encryption_key = match perform_key_exchange(&mut tls_stream).await {
            Ok(key) => key,
            Err(e) => {
                error_handler::log_and_display_error("Failed to perform key exchange", &e);
                reconnect_attempts += 1;
                if reconnect_attempts >= config.max_reconnect_attempts {
                    return Err("Max reconnect attempts reached".into());
                }
                tokio::time::sleep(config.reconnect_delay).await;
                continue;
            }
        };

        let session_token = match get_or_receive_session_token(&mut tls_stream).await {
            Ok(token) => token,
            Err(e) => {
                error_handler::log_and_display_error("Failed to get or receive session token", &e);
                reconnect_attempts += 1;
                if reconnect_attempts >= config.max_reconnect_attempts {
                    return Err("Max reconnect attempts reached".into());
                }
                tokio::time::sleep(config.reconnect_delay).await;
                continue;
            }
        };

        if let Err(e) = send_proof_and_verifying_key(&mut tls_stream, &session_token).await {
            error_handler::log_and_display_error("Failed to send proof and verifying key", &e);
            reconnect_attempts += 1;
            if reconnect_attempts >= config.max_reconnect_attempts {
                return Err("Max reconnect attempts reached".into());
            }
            tokio::time::sleep(config.reconnect_delay).await;
            continue;
        }

        let session_token_array: [u8; 32] = session_token.try_into().unwrap();

        if let Err(e) = handle_connection(&mut tls_stream, &encryption_key, &session_token_array, &config).await {
            error_handler::log_and_display_error("Connection error", &e);
            reconnect_attempts += 1;
            if reconnect_attempts >= config.max_reconnect_attempts {
                return Err("Max reconnect attempts reached".into());
            }
            tokio::time::sleep(config.reconnect_delay).await;
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
    let mut tls_stream = tls_connector.connect("localhost", stream).await?;

    // Receive the TLS certificate proof and verifying key from the server
    let mut tls_certificate_proof = Vec::new();
    tls_stream.read_to_end(&mut tls_certificate_proof).await?;

    let mut tls_certificate_verifying_key = Vec::new();
    tls_stream.read_to_end(&mut tls_certificate_verifying_key).await?;

    // Verify the TLS certificate proof
    let tls_certificate_proof_result = verify_tls_certificate_proof(&tls_certificate_proof, &tls_certificate_verifying_key)
        .map_err(|e| format!("Failed to verify TLS certificate proof: {}", e))?;

    if !tls_certificate_proof_result {
        error_handler::log_warning("Warning: Potential MITM attack or NGFW detected. TLS certificate proof verification failed.");
    }

    Ok(tls_stream)
}

async fn perform_key_exchange(
    tls_stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let (ephemeral_secret, ephemeral_public) = encryption::generate_key_pair();

    // Generate the TLS certificate proof
    let peer_cert = tls_stream.get_ref().peer_certificate().unwrap().unwrap();
    let der_cert = peer_cert.to_der().unwrap();
    let (tls_certificate_proof, tls_certificate_verifying_key) = generate_tls_certificate_proof(&der_cert)
        .map_err(|e| format!("Failed to generate TLS certificate proof: {}", e))?;

    // Send the TLS certificate proof and verifying key to the server
    tls_stream.write_all(&tls_certificate_proof).await?;
    tls_stream.write_all(&tls_certificate_verifying_key).await?;

    // Receive the server's public key
    let mut server_public_bytes = [0u8; 32];
    tls_stream.read_exact(&mut server_public_bytes).await?;
    let server_public = PublicKey::from(server_public_bytes);

    // Send the client's public key to the server
    let public_key_bytes = ephemeral_public.as_bytes().to_vec();
    tls_stream.write_all(&public_key_bytes).await?;

    let shared_secret: x25519_dalek::SharedSecret;

    // Verify the TLS certificate proof
    let tls_certificate_proof_result = verify_tls_certificate_proof(&tls_certificate_proof, &tls_certificate_verifying_key)
        .map_err(|e| format!("Failed to verify TLS certificate proof: {}", e))?;

    if !tls_certificate_proof_result {
        error_handler::log_warning("Warning: Potential MITM attack or NGFW detected. TLS certificate proof verification failed.");

        // Receive the server's PFS public key proof and verifying key
        let mut server_pfs_proof = Vec::new();
        tls_stream.read_to_end(&mut server_pfs_proof).await?;

        let mut server_pfs_verifying_key = Vec::new();
        tls_stream.read_to_end(&mut server_pfs_verifying_key).await?;

        // Verify the server's PFS public key proof
        let server_pfs_proof_result = verify_pfs_public_key_proof(&server_pfs_proof, &server_pfs_verifying_key)
            .map_err(|e| format!("Failed to verify server's PFS public key proof: {}", e))?;

        if !server_pfs_proof_result {
            error_handler::log_and_display_error("Server's PFS public key proof verification failed. Authentication tampered with mid-stream.", &"");
            return Err("Server's PFS public key proof verification failed".into());
        }

        // Generate the client's PFS public key proof
        let (client_pfs_proof, client_pfs_verifying_key) = generate_pfs_public_key_proof(ephemeral_public.as_bytes())
            .map_err(|e| format!("Failed to generate client's PFS public key proof: {}", e))?;

        // Send the client's PFS public key proof and verifying key to the server
        tls_stream.write_all(&client_pfs_proof).await?;
        tls_stream.write_all(&client_pfs_verifying_key).await?;

        // Derive the shared secret using the client's ephemeral secret key and the server's public key
        shared_secret = ephemeral_secret.diffie_hellman(&server_public);
    } else {
        // Derive the shared secret using the client's ephemeral secret key and the server's public key
        shared_secret = ephemeral_secret.diffie_hellman(&server_public);
    }

    let encryption_key = encryption::derive_encryption_key(&shared_secret)
        .map_err(|e| format!("Failed to derive encryption key: {}", e))?;

    Ok(encryption_key)
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
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encryption_key = Key::from_slice(encryption_key).unwrap();
    fs::write("session_token.bin", session_token)?;

    let mut buf = [0u8; 1024];
    let start_time = std::time::Instant::now();

    loop {
        let elapsed_time = start_time.elapsed();
        if elapsed_time >= config.session_lifetime {
            // Session has reached its maximum duration, renegotiate the session
            return Ok(());
        }

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