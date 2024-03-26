use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::groth16::{generate_random_parameters, create_random_proof, prepare_verifying_key, verify_proof};
use bls12_381::Bls12;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// Define the circuit for token ownership proof
#[derive(Clone)]
struct TokenOwnershipCircuit {
    token_hash: Vec<u8>,
}

impl Circuit<bls12_381::Scalar> for TokenOwnershipCircuit {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let token_hash_bits = bellman::gadgets::multipack::bytes_to_bits_le(&self.token_hash);
        let token_hash_value = token_hash_bits
            .into_iter()
            .map(|bit| bellman::gadgets::boolean::Boolean::from(bellman::gadgets::boolean::AllocatedBit::alloc(
                cs.namespace(|| "token_hash_bit"),
                Some(bit)
            ).unwrap()))
            .collect::<Vec<_>>();

        cs.enforce(
            || "token_hash_constraint",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| {
                let mut result = lc;
                for bit in token_hash_value.iter() {
                    let scalar = bls12_381::Scalar::from(bit.get_value().unwrap() as u64);
                    result = result + (scalar, CS::one());
                }
                result
            },
        );

        Ok(())
    }
}

// Generate the token ownership proof
pub fn generate_token_ownership_proof(token: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let token_hash = Sha256::digest(token).to_vec();
    let circuit = TokenOwnershipCircuit { token_hash };
    let params = {
        let mut rng = OsRng;
        generate_random_parameters::<Bls12, _, _>(circuit.clone(), &mut rng)?
    };
    let proof = {
        let mut rng = OsRng;
        create_random_proof(circuit, &params, &mut rng)?
    };

    let mut proof_vec = Vec::new();
    proof.write(&mut proof_vec)?;
    let mut verifying_key_vec = Vec::new();
    params.vk.write(&mut verifying_key_vec)?;

    Ok((proof_vec, verifying_key_vec))
}

// Verify the token ownership proof
pub fn verify_token_ownership_proof(proof: &[u8], verifying_key: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let vk = bellman::groth16::VerifyingKey::<Bls12>::read(&mut &verifying_key[..])?;
    let pvk = prepare_verifying_key(&vk);
    let proof = bellman::groth16::Proof::<Bls12>::read(&mut &proof[..])?;

    match verify_proof(&pvk, &proof, &[]) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// Define the circuit for TLS certificate proof
#[derive(Clone)]
struct TLSCertificateCircuit {
    certificate_hash: Vec<u8>,
}

impl Circuit<bls12_381::Scalar> for TLSCertificateCircuit {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let certificate_hash_bits = bellman::gadgets::multipack::bytes_to_bits_le(&self.certificate_hash);
        let certificate_hash_value = certificate_hash_bits
            .into_iter()
            .map(|bit| bellman::gadgets::boolean::Boolean::from(bellman::gadgets::boolean::AllocatedBit::alloc(
                cs.namespace(|| "certificate_hash_bit"),
                Some(bit)
            ).unwrap()))
            .collect::<Vec<_>>();

        cs.enforce(
            || "certificate_hash_constraint",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| {
                let mut result = lc;
                for bit in certificate_hash_value.iter() {
                    let scalar = bls12_381::Scalar::from(bit.get_value().unwrap() as u64);
                    result = result + (scalar, CS::one());
                }
                result
            },
        );

        Ok(())
    }
}

// Generate the TLS certificate proof
pub fn generate_tls_certificate_proof(certificate: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let certificate_hash = Sha256::digest(certificate).to_vec();
    let circuit = TLSCertificateCircuit { certificate_hash };
    let params = {
        let mut rng = OsRng;
        generate_random_parameters::<Bls12, _, _>(circuit.clone(), &mut rng)?
    };
    let proof = {
        let mut rng = OsRng;
        create_random_proof(circuit, &params, &mut rng)?
    };

    let mut proof_vec = Vec::new();
    proof.write(&mut proof_vec)?;
    let mut verifying_key_vec = Vec::new();
    params.vk.write(&mut verifying_key_vec)?;

    Ok((proof_vec, verifying_key_vec))
}

// Verify the TLS certificate proof
pub fn verify_tls_certificate_proof(proof: &[u8], verifying_key: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let vk = bellman::groth16::VerifyingKey::<Bls12>::read(&mut &verifying_key[..])?;
    let pvk = prepare_verifying_key(&vk);
    let proof = bellman::groth16::Proof::<Bls12>::read(&mut &proof[..])?;

    match verify_proof(&pvk, &proof, &[]) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// Define the circuit for PFS public key proof
#[derive(Clone)]
struct PFSPublicKeyCircuit {
    public_key: Vec<u8>,
}

impl Circuit<bls12_381::Scalar> for PFSPublicKeyCircuit {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let public_key_bits = bellman::gadgets::multipack::bytes_to_bits_le(&self.public_key);
        let public_key_value = public_key_bits
            .into_iter()
            .map(|bit| bellman::gadgets::boolean::Boolean::from(bellman::gadgets::boolean::AllocatedBit::alloc(
                cs.namespace(|| "public_key_bit"),
                Some(bit)
            ).unwrap()))
            .collect::<Vec<_>>();

        cs.enforce(
            || "public_key_constraint",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| {
                let mut result = lc;
                for bit in public_key_value.iter() {
                    let scalar = bls12_381::Scalar::from(bit.get_value().unwrap() as u64);
                    result = result + (scalar, CS::one());
                }
                result
            },
        );

        Ok(())
    }
}

// Generate the PFS public key proof
pub fn generate_pfs_public_key_proof(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let circuit = PFSPublicKeyCircuit { public_key: public_key.to_vec() };
    let params = {
        let mut rng = OsRng;
        generate_random_parameters::<Bls12, _, _>(circuit.clone(), &mut rng)?
    };
    let proof = {
        let mut rng = OsRng;
        create_random_proof(circuit, &params, &mut rng)?
    };

    let mut proof_vec = Vec::new();
    proof.write(&mut proof_vec)?;
    let mut verifying_key_vec = Vec::new();
    params.vk.write(&mut verifying_key_vec)?;

    Ok((proof_vec, verifying_key_vec))
}

// Verify the PFS public key proof
pub fn verify_pfs_public_key_proof(proof: &[u8], verifying_key: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let vk = bellman::groth16::VerifyingKey::<Bls12>::read(&mut &verifying_key[..])?;
    let pvk = prepare_verifying_key(&vk);
    let proof = bellman::groth16::Proof::<Bls12>::read(&mut &proof[..])?;

    match verify_proof(&pvk, &proof, &[]) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}