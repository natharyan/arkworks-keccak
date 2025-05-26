use ark_ff::Field;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use bitvec::order::Lsb0;
use bitvec::prelude::BitVec;
use sha3::{
    Digest, Sha3_256, Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use tiny_keccak::{Hasher, Keccak};

pub fn bytes_to_bitvec<F: Field>(bytes: &[u8]) -> Vec<Boolean<F>> {
    let bits = BitVec::<u8, Lsb0>::from_slice(bytes);
    let bits: Vec<Boolean<F>> = bits.iter().map(|b| Boolean::constant(*b)).collect();
    bits
}

pub fn bits_to_bytevec<F: Field>(bits: &[Boolean<F>]) -> Vec<u8> {
    let result: Vec<bool> = bits.iter().map(|b| b.value().unwrap()).collect();
    let mut bv = BitVec::<u8, Lsb0>::new();
    for bit in result {
        bv.push(bit);
    }
    bv.as_raw_slice().to_vec()
}

pub fn vec_to_public_input<F: Field>(
    cs: ConstraintSystemRef<F>,
    namespace: &'static str,
    input: Vec<Boolean<F>>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    input
        .into_iter()
        .map(|bit| {
            let ns = match namespace {
                "preimage" => ark_relations::ns!(cs, "preimage"),
                "expected" => ark_relations::ns!(cs, "expected"),
                _ => panic!("Unsupported namespace"),
            };

            AllocVar::new_input(ns, || Ok(bit.value().unwrap()))
        })
        .collect()
}

// functions for UInt64
pub fn not<F: Field>(x: &UInt64<F>) -> Result<UInt64<F>, SynthesisError> {
    let xbits = x.to_bits_le();
    let mut notx = Vec::with_capacity(64);
    for i in 0..64 {
        notx.push(xbits[i].not());
    }
    Ok(UInt64::from_bits_le(&notx))
}

pub fn and<F: Field>(x: &UInt64<F>, y: &UInt64<F>) -> Result<UInt64<F>, SynthesisError> {
    let xbits = x.to_bits_le();
    let ybits = y.to_bits_le();
    let mut x_and_y = Vec::with_capacity(64);
    for i in 0..64 {
        x_and_y.push(Boolean::and(&xbits[i], &ybits[i])?);
    }
    Ok(UInt64::from_bits_le(&x_and_y))
}

pub fn rotl<F: Field>(x: &UInt64<F>, shift: usize) -> Result<UInt64<F>, SynthesisError> {
    // ROTL = 64 - ROTR
    let shift = (64 - shift) % 64;
    let bitvec = x.to_bits_le();
    let mut rotatedvec = Vec::with_capacity(64);
    for i in 0..64 {
        rotatedvec.push(bitvec[(i + shift) % 64].clone());
    }
    Ok(UInt64::from_bits_le(&rotatedvec))
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    tiny_keccak::Hasher::update(&mut hasher, input);
    hasher.finalize(&mut output);
    output
}

pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Update::update(&mut hasher, input);
    let result: [u8; 32] = hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("Wrong length");
    result
}

pub fn shake_128(input: &[u8]) -> [u8; 16] {
    let mut hasher = Shake128::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut result = [0u8; 16];
    XofReader::read(&mut reader, &mut result);
    result
}

pub fn shake_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut result = [0u8; 32];
    XofReader::read(&mut reader, &mut result);
    result
}
