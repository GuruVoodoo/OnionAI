use std::io;
use tokio::fs as tokio_fs;

pub async fn check_or_generate_tls_key() -> Result<String, io::Error> {
    let public_key_file = "tls_public_key.pem";

    if tokio_fs::metadata(public_key_file).await.is_ok() {
        println!("TLS public key file exists: {}", public_key_file);
    } else {
        match generate_tls_public_key(public_key_file).await {
            Ok(()) => println!("New TLS public key generated and saved to: {}", public_key_file),
            Err(err) => eprintln!("Error generating TLS public key: {}", err),
        }
    }

    Ok(public_key_file.to_string())
}

async fn generate_tls_public_key(file_name: &str) -> Result<(), io::Error> {
    let rsa_key_pair = openssl::rsa::Rsa::generate(2048)?;

    let public_key_pem = rsa_key_pair.public_key_to_pem()?;

    let mut file = tokio_fs::File::create(file_name).await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, &public_key_pem).await?;

    Ok(())
}

pub async fn read_tls_key_contents(file_name: &str) -> Result<String, io::Error> {
    tokio_fs::read_to_string(file_name).await
}
