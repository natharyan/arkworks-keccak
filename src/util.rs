use ark_ff::{Field, PrimeField};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use bitvec::order::Lsb0;
use bitvec::prelude::BitVec;
use keccak::f1600;
use sha3::{
    Digest, Keccak256, Sha3_256, Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

// utility functions for UInt64
pub trait UInt64Extensions<F: Field> {
    fn not(&self) -> Result<UInt64<F>, SynthesisError>;
    fn and(&self, other: &UInt64<F>) -> Result<UInt64<F>, SynthesisError>;
    fn rotl(&self, shift: usize) -> Result<UInt64<F>, SynthesisError>;
}

impl<F: Field> UInt64Extensions<F> for UInt64<F> {
    fn not(&self) -> Result<UInt64<F>, SynthesisError> {
        let xbits = self.to_bits_le();
        let mut notx = Vec::with_capacity(64);
        for i in 0..64 {
            notx.push(xbits[i].not());
        }
        Ok(UInt64::from_bits_le(&notx))
    }

    fn and(&self, other: &UInt64<F>) -> Result<UInt64<F>, SynthesisError> {
        let xbits = self.to_bits_le();
        let ybits = other.to_bits_le();
        let mut x_and_y = Vec::with_capacity(64);
        for i in 0..64 {
            x_and_y.push(Boolean::and(&xbits[i], &ybits[i])?);
        }
        Ok(UInt64::from_bits_le(&x_and_y))
    }

    fn rotl(&self, shift: usize) -> Result<UInt64<F>, SynthesisError> {
        // ROTL = 64 - ROTR
        let shift = (64 - shift) % 64;
        let bitvec = self.to_bits_le();
        let mut rotatedvec = Vec::with_capacity(64);
        for i in 0..64 {
            rotatedvec.push(bitvec[(i + shift) % 64].clone());
        }
        Ok(UInt64::from_bits_le(&rotatedvec))
    }
}

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

fn vec_bool_to_arr_u64<F: PrimeField>(input: Vec<Boolean<F>>) -> [u64; 25] {
    let mut input_u64: [u64; 25] = [0; 25];
    for (i, chunk) in input.chunks(64).enumerate() {
        let mut word = 0u64;
        for (bit_idx, bit) in chunk.iter().enumerate() {
            if bit.value().unwrap_or(false) {
                word |= 1u64 << bit_idx; // Little-endian bit order
            }
        }
        input_u64[i] = word;
    }

    input_u64
}

fn arr_u64_to_vec_bool<F: PrimeField>(input: &[u64; 25]) -> Vec<Boolean<F>> {
    input
        .iter()
        .flat_map(|word| {
            (0..64).map(move |i| {
                Boolean::constant((word >> i) & 1 == 1) // Extract each bit and convert to Boolean<F>
            })
        })
        .collect()
}

pub fn libary_f1600_to_bool<F: PrimeField>(input: Vec<Boolean<F>>) -> Vec<Boolean<F>> {
    let mut input_arr_u64 = vec_bool_to_arr_u64(input);
    f1600(&mut input_arr_u64);
    arr_u64_to_vec_bool::<F>(&input_arr_u64)
}

/// One step of the absorption (flag = 0) or squeezing phase (flag = 1)
pub fn libary_step_sponge<F: PrimeField>(
    mut state: Vec<Boolean<F>>,
    m_i: Option<Vec<Boolean<F>>>,
    r: usize,
    flag: Boolean<F>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    if flag == Boolean::constant(false) {
        if let Some(m_i) = m_i {
            // println!("Absorption step");
            for i in 0..r {
                state[i] = Boolean::xor(&state[i], &m_i[i])?;
            }
        } else {
            return Err(SynthesisError::AssignmentMissing);
        }
    } else {
        // println!("Squeezing step");
        // No m_i required
    }

    let mut input_arr_u64 = vec_bool_to_arr_u64(state);
    f1600(&mut input_arr_u64);
    Ok(arr_u64_to_vec_bool::<F>(&input_arr_u64))
}

// TODO: generalise output length
pub fn keccak256(input: &[u8], _d: usize) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    Update::update(&mut hasher, input);
    let result: Vec<u8> = hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("Wrong length");
    result
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

pub fn shake_128(input: &[u8], d: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut result = vec![0u8; d];
    XofReader::read(&mut reader, &mut result);
    result
}

pub fn shake_256(input: &[u8], d: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut result = vec![0u8; d];
    XofReader::read(&mut reader, &mut result);
    result
}
