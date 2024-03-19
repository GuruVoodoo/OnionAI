use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::{Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

pub fn derive_encryption_key(shared_secret: &SharedSecret) -> Result<Vec<u8>, hkdf::InvalidLength> {
    let salt = sodiumoxide::randombytes::randombytes(32); // Generate random salt
    let info = b"encryption_key";

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());  // Correct arguments for Hkdf::new
    let mut key_material = vec![0u8; 32]; // Create a mutable buffer for key material

    hkdf.expand(info, &mut key_material)?; // Use mutable reference and handle Result

    Ok(key_material) // Return the derived key material
}

pub fn encrypt(message: &[u8], key: &Key, nonce: &Nonce) -> Vec<u8> {
    let ciphertext = secretbox::seal(message, nonce, key);
    let mut pmc_ciphertext = Vec::new();
    pmc_ciphertext.extend_from_slice(&ciphertext[0..16]); // PMC header
    pmc_ciphertext.extend_from_slice(&ciphertext[24..]); // PMC encrypted message
    pmc_ciphertext
}

pub fn decrypt(ciphertext: &[u8], key: &Key, nonce: &Nonce) -> Option<Vec<u8>> {
    let mut full_ciphertext = Vec::with_capacity(ciphertext.len() + 16);
    full_ciphertext.extend_from_slice(&ciphertext[0..16]); // PMC header
    full_ciphertext.extend_from_slice(&[0u8; 8]); // PMC placeholder
    full_ciphertext.extend_from_slice(&ciphertext[16..]); // PMC encrypted message
    secretbox::open(&full_ciphertext, nonce, key).ok()
}

pub fn generate_secure_seed() -> [u8; 32] {
    // Generate a secure random seed for the CSPRNG
    let mut seed = [0u8; 32];
    // Use a secure source of randomness to fill the seed, e.g., OsRng
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

pub fn generate_key_pair() -> (EphemeralSecret, PublicKey) {
    let mut rng = ChaCha20Rng::from_seed(generate_secure_seed());
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    (ephemeral_secret, ephemeral_public)
}