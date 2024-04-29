use crate::config::AppConfig;
use crate::encryption;
use crate::error_handler;
use crate::key;
use crate::zk_proof::{generate_token_ownership_proof, generate_tls_certificate_proof, verify_tls_certificate_proof, generate_pfs_public_key_proof, verify_pfs_public_key_proof};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Key, Nonce};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Sender, Receiver};
use tokio_native_tls::TlsConnector;
use x25519_dalek::PublicKey;
use openssl::pkcs12::Pkcs12;

pub async fn connect_to_node(
    config: AppConfig,
    target_addr: SocketAddr,
    mut message_sender: Sender<String>,
    mut message_receiver: Receiver<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Obtain the private key and certificate from check_or_generate_tls_key
    let (private_key, certificate) = match key::check_or_generate_tls_key().await {
        Ok((private_key, certificate)) => (private_key, certificate),
        Err(e) => {
            error_handler::log_and_display_error("Error checking or generating TLS key pair", &e);
            return Err("Failed to obtain TLS key pair".into());
        }
    };

// Bundle the private key and certificate into a PKCS12 archive
    let password = ""; // or the actual password if you have one
    let pkcs12 = match Pkcs12::builder()
        .name("friendly_name")
        .pkey(&private_key)
        .cert(&certificate)
        .build2("") {
        Ok(pkcs12) => pkcs12,
        Err(e) => {
            error_handler::log_and_display_error("Error building PKCS12 archive", &e);
            return Err("Failed to build PKCS12 archive".into());
        }
    };

// Create the identity using the generated PKCS12 archive
    let der = pkcs12.to_der().unwrap();
    let identity = match native_tls::Identity::from_pkcs12(&der, password) {
        Ok(identity) => identity,
        Err(e) => {
            error_handler::log_and_display_error("Error creating identity from PKCS12 archive", &e);
            return Err("Failed to create identity from PKCS12 archive".into());
        }
    };

    let tls_connector = TlsConnector::from(native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .identity(identity)
        .build()
        .unwrap());

    let stream = TcpStream::connect(&target_addr).await?;
    let mut tls_stream = tls_connector.connect(&target_addr.to_string(), stream).await?;

    // Receive the server's TLS certificate proof and verifying key
    let mut server_tls_proof = Vec::new();
    tls_stream.read_to_end(&mut server_tls_proof).await.expect("Failed to receive server's TLS certificate proof");

    let mut server_tls_verifying_key = Vec::new();
    tls_stream.read_to_end(&mut server_tls_verifying_key).await.expect("Failed to receive server's TLS certificate verifying key");

    // Verify the server's TLS certificate proof
    let server_tls_proof_result = verify_tls_certificate_proof(&server_tls_proof, &server_tls_verifying_key)
        .expect("Failed to verify server's TLS certificate proof");

    if !server_tls_proof_result {
        error_handler::log_warning("Warning: Potential MITM attack or NGFW detected. Server's TLS certificate proof verification failed.");
        return Err("Server's TLS certificate proof verification failed".into());
    }

    // Generate the client's TLS certificate proof
    let client_cert_der = certificate.to_der().expect("Failed to encode client certificate to DER");
    let (client_tls_proof, client_tls_verifying_key) = generate_tls_certificate_proof(&client_cert_der)
        .expect("Failed to generate client's TLS certificate proof");

    // Send the client's TLS certificate proof and verifying key to the server
    tls_stream.write_all(&client_tls_proof).await.expect("Failed to send client's TLS certificate proof");
    tls_stream.write_all(&client_tls_verifying_key).await.expect("Failed to send client's TLS certificate verifying key");


    let encryption_key = perform_key_exchange(&mut tls_stream).await?;

    let session_token = get_or_receive_session_token(&mut tls_stream).await?;

    send_proof_and_verifying_key(&mut tls_stream, &session_token).await?;

    let session_token_array: [u8; 32] = session_token.try_into().unwrap();

    handle_connection(&mut tls_stream, &encryption_key, &session_token_array, &config, &mut message_sender, &mut message_receiver).await?;

    Ok(())
}

async fn perform_key_exchange(
    tls_stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let (ephemeral_secret, ephemeral_public) = encryption::generate_key_pair();

    // Receive the server's public key
    let mut server_public_bytes = [0u8; 32];
    tls_stream.read_exact(&mut server_public_bytes).await?;
    let server_public = PublicKey::from(server_public_bytes);

    // Send the client's public key to the server
    let public_key_bytes = ephemeral_public.as_bytes().to_vec();
    tls_stream.write_all(&public_key_bytes).await?;

    let shared_secret: x25519_dalek::SharedSecret;

    // Generate the TLS certificate proof
    let peer_cert = tls_stream.get_ref().peer_certificate().unwrap().unwrap();
    let der_cert = peer_cert.to_der().unwrap();
    let (tls_certificate_proof, tls_certificate_verifying_key) = generate_tls_certificate_proof(&der_cert)
        .map_err(|e| format!("Failed to generate TLS certificate proof: {}", e))?;

    // Send the TLS certificate proof and verifying key to the server
    tls_stream.write_all(&tls_certificate_proof).await?;
    tls_stream.write_all(&tls_certificate_verifying_key).await?;

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
        let session_token = std::fs::read(session_token_path)?;
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
    message_sender: &mut Sender<String>,
    message_receiver: &mut Receiver<String>,
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

        let received_message = String::from_utf8_lossy(&plaintext).to_string();
        message_sender.send(received_message).await.expect("Failed to send message to GUI");

        // Receive messages from the GUI and send them encrypted to the server
        if let Some(message) = message_receiver.recv().await {
            let ciphertext = encryption::encrypt(message.as_bytes(), &encryption_key, &nonce);

            if let Err(e) = tls_stream.write_all(&ciphertext).await {
                error_handler::log_and_display_error("Error sending message", &e);
                return Err(e.into());
            }
        }
    }

    Ok(())
}