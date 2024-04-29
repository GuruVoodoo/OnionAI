use std::io;
use std::sync::{Arc, Mutex};
use tokio::fs as tokio_fs;
use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::hash::MessageDigest;
use openssl::x509::X509NameBuilder;
use ring::aead::{Nonce, NonceSequence, BoundKey, OpeningKey, SealingKey, AES_256_GCM, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;
use openssl::pkcs12::Pkcs12;
use openssl::asn1::Asn1Time;


struct CounterNonceSequence(u64);

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&self.0.to_be_bytes());
        self.0 = self.0.checked_add(1).ok_or(ring::error::Unspecified)?;

        Ok(Nonce::assume_unique_for_key(nonce))
    }
}
struct LessSafeKeyWrapper {
    unbound_key: Arc<Mutex<UnboundKey>>,
    key: [u8; 32],
}

impl Drop for LessSafeKeyWrapper {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Zeroize for LessSafeKeyWrapper {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Default for LessSafeKeyWrapper {
    fn default() -> Self {
        let key = [0; 32];
        LessSafeKeyWrapper {
            unbound_key: Arc::new(Mutex::new(UnboundKey::new(&AES_256_GCM, &key).unwrap())),
            key,
        }
    }
}

struct EncryptionKey(Secret<LessSafeKeyWrapper>);
impl EncryptionKey {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).unwrap();
        let unbound_key = Arc::new(Mutex::new(UnboundKey::new(&AES_256_GCM, &key).unwrap()));
        EncryptionKey(Secret::new(LessSafeKeyWrapper { unbound_key, key }))
    }

    fn sealing_key(&self) -> SealingKey<CounterNonceSequence> {
        let wrapper = self.0.expose_secret();
        let key = UnboundKey::new(&AES_256_GCM, &wrapper.key).unwrap();
        SealingKey::new(key, CounterNonceSequence(0))
    }

    fn opening_key(&self) -> OpeningKey<CounterNonceSequence> {
        let wrapper = self.0.expose_secret();
        let key = UnboundKey::new(&AES_256_GCM, &wrapper.key).unwrap();
        OpeningKey::new(key, CounterNonceSequence(0))
    }
}

pub async fn check_or_generate_tls_key() -> Result<(PKey<Private>, X509), io::Error> {
    let private_key_file = "tls_private_key.enc";
    let certificate_file = "tls_certificate.enc";
    let encryption_key_file = "encryption_key.enc";

    match read_encryption_key(encryption_key_file).await {
        Ok(encryption_key) => {
            match read_private_key(private_key_file, &encryption_key).await {
                Ok(private_key) => {
                    match read_certificate(certificate_file, &encryption_key).await {
                        Ok(certificate) => {
                            println!("TLS private key and certificate files exist and are valid: {} and {}", private_key_file, certificate_file);
                            Ok((private_key, certificate))
                        },
                        Err(err) => {
                            eprintln!("Error reading TLS certificate: {}", err);
                            regenerate_tls_key_pair(private_key_file, certificate_file, encryption_key_file).await
                        }
                    }
                },
                Err(err) => {
                    eprintln!("Error reading TLS private key: {}", err);
                    regenerate_tls_key_pair(private_key_file, certificate_file, encryption_key_file).await
                }
            }
        },
        Err(err) => {
            eprintln!("Error reading encryption key: {}", err);
            regenerate_tls_key_pair(private_key_file, certificate_file, encryption_key_file).await
        }
    }
}


async fn regenerate_tls_key_pair(private_key_file: &str, certificate_file: &str, encryption_key_file: &str) -> Result<(PKey<Private>, X509), io::Error> {
    println!("Regenerating TLS key pair...");
    let encryption_key = EncryptionKey::new();
    match generate_tls_key_pair(private_key_file, certificate_file, &encryption_key).await {
        Ok((private_key, certificate)) => {
            store_encryption_key(encryption_key_file, &encryption_key).await?;
            println!("New TLS key pair generated and saved to: {} and {}", private_key_file, certificate_file);
            Ok((private_key, certificate))
        },
        Err(err) => {
            eprintln!("Error generating TLS key pair: {}", err);
            Err(err)
        },
    }
}

async fn generate_tls_key_pair(private_key_file: &str, certificate_file: &str, encryption_key: &EncryptionKey) -> Result<(PKey<Private>, X509), io::Error> {
    // Generate a new private key
    let rsa_key_pair = Rsa::generate(2048)?;
    let private_key = PKey::from_rsa(rsa_key_pair)?;

    // Generate a self-signed certificate
    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("CN", "localhost").unwrap();
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder.set_subject_name(&x509_name).unwrap();
    cert_builder.set_issuer_name(&x509_name).unwrap();
    cert_builder.set_pubkey(&private_key).unwrap();
    cert_builder.sign(&private_key, MessageDigest::sha256()).unwrap();

    // Set the validity period of the certificate
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();

    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert_builder.x509v3_context(None, None))
        .unwrap();
    cert_builder.append_extension(subject_alternative_name).unwrap();

    let certificate = cert_builder.build();

    // Create a PKCS12 archive containing the private key and certificate
    let mut pkcs12_builder = openssl::pkcs12::Pkcs12::builder();
    let pkcs12 = pkcs12_builder
        .name("tls_key_pair")
        .pkey(&private_key)
        .cert(&certificate)
        .build2("")
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Error creating PKCS12 archive: {}", err),))?;

    let pkcs12_der = pkcs12.to_der().map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Error encoding PKCS12 archive: {}", err),
        )
    })?;

    // Encrypt the PKCS12 archive
    let encrypted_pkcs12 = encrypt_data(&pkcs12_der, encryption_key)?;

    // Write the encrypted PKCS12 archive to the private key file
    let mut private_key_file = tokio_fs::File::create(private_key_file).await?;
    tokio::io::AsyncWriteExt::write_all(&mut private_key_file, &encrypted_pkcs12).await?;

    // Write the certificate to the certificate file
    let certificate_pem = certificate.to_pem()?;
    let encrypted_certificate = encrypt_data(&certificate_pem, encryption_key)?;
    let mut certificate_file = tokio_fs::File::create(certificate_file).await?;
    tokio::io::AsyncWriteExt::write_all(&mut certificate_file, &encrypted_certificate).await?;

    Ok((private_key, certificate))
}

async fn read_private_key(file_name: &str, encryption_key: &EncryptionKey) -> Result<PKey<Private>, io::Error> {
    let encrypted_private_key = tokio_fs::read(file_name).await?;
    let private_key_pkcs12 = decrypt_data(&encrypted_private_key, encryption_key)?;
    let pkcs12 = Pkcs12::from_der(&private_key_pkcs12)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid PKCS12 archive: {}", err),
            )
        })?;

    let parsed_pkcs12 = pkcs12.parse2("")?;
    Ok(parsed_pkcs12.pkey.expect("Expected a key"))
}

async fn read_certificate(file_name: &str, encryption_key: &EncryptionKey) -> Result<X509, io::Error> {
    let encrypted_certificate = tokio_fs::read(file_name).await?;
    let certificate_pem = decrypt_data(&encrypted_certificate, encryption_key)?;
    let certificate = X509::from_pem(&certificate_pem)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid certificate: {}", err)))?;
    Ok(certificate)
}


async fn store_encryption_key(file_name: &str, encryption_key: &EncryptionKey) -> Result<(), io::Error> {
    let wrapper = encryption_key.0.expose_secret();
    let key_bytes = &wrapper.key;

    let mut file = tokio_fs::File::create(file_name).await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Error creating file: {}", err)))?;

    tokio::io::AsyncWriteExt::write_all(&mut file, key_bytes).await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Error writing to file: {}", err)))?;

    Ok(())
}

async fn read_encryption_key(file_name: &str) -> Result<EncryptionKey, io::Error> {
    let encrypted_key = tokio_fs::read(file_name).await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Error reading file: {}", err)))?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&encrypted_key[..32]);

    let unbound_key = Arc::new(Mutex::new(UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("Error creating unbound key: {}", err)))?));

    Ok(EncryptionKey(Secret::new(LessSafeKeyWrapper { unbound_key, key: key_bytes })))
}

fn encrypt_data(data: &[u8], encryption_key: &EncryptionKey) -> Result<Vec<u8>, io::Error> {
    let mut sealing_key = encryption_key.sealing_key();
    let mut nonce_bytes = [0; 12];
    SystemRandom::new().fill(&mut nonce_bytes).unwrap();
    let _nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut buffer = data.to_vec();
    buffer.extend_from_slice(&nonce_bytes);
    sealing_key.seal_in_place_append_tag(ring::aead::Aad::empty(), &mut buffer)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;
    Ok(buffer)
}

fn decrypt_data(encrypted_data: &[u8], encryption_key: &EncryptionKey) -> Result<Vec<u8>, io::Error> {
    let mut opening_key = encryption_key.opening_key();
    let mut buffer = encrypted_data.to_vec();
    let plain_data = opening_key.open_in_place(ring::aead::Aad::empty(), &mut buffer)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Decryption failed"))?;
    Ok(plain_data.to_vec())
}