use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::uint64::UInt64;
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};
use ark_ff::Field;

pub type ConstraintF = ark_bls12_381::Fq;


// functions for UInt64
pub fn not<F: Field>(x: &UInt64<F>) -> Result<UInt64<F>, SynthesisError>{
    let xbits = x.to_bits_le();
    let mut notx = Vec::with_capacity(64);
    for i in 0..64{
        notx.push(xbits[i].not());
    }
    Ok(UInt64::from_bits_le(&notx))
}

pub fn and<F: Field>(x: &UInt64<F>, y: &UInt64<F>) -> Result<UInt64<F>, SynthesisError>{
    let xbits = x.to_bits_le();
    let ybits = y.to_bits_le();
    let mut x_and_y = Vec::with_capacity(64);
    for i in 0..64{
        x_and_y.push(Boolean::and(&xbits[i],&ybits[i])?);
    }
    Ok(UInt64::from_bits_le(&x_and_y))
}

pub fn rotl<F: Field>(x: &UInt64<F>, shift: usize) -> Result<UInt64<F>, SynthesisError>{
    let bitvec = x.to_bits_le();
    let mut rotatedvec = Vec::with_capacity(64);
    for i in 0..64{
        rotatedvec.push(bitvec[(i + shift) % 64].clone());
    }
    Ok(UInt64::from_bits_le(&rotatedvec))
}