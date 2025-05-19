use ark_bls12_381::Fr;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

// round constants for the \iota mapping
#[rustfmt::skip]
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

// rotation array ROTR for the \rho mapping
const ROTR: [usize; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

// xor_2
fn xor_2<ConstraintF>(mut cs: ConstraintSystemRef<ConstraintF>, a: &UInt64<ConstraintF>, b: &UInt64<ConstraintF>) -> Result<UInt64<ConstraintF>, SynthesisError>
    {
        // a^b
        // TODO: implement xor with the UInt64 gadget
        let xor_2 = UInt64::new_witness(ark_relations::ns!(cs, "xor_2"), || {Ok(a.xor(b))})?;
        Ok(xor_2)
    }

// xor_5
fn xor_5<ConstraintF>(
    mut cs: ConstraintSystemRef<ConstraintF>,
    a: &UInt64<ConstraintF>,
    b: &UInt64<ConstraintF>,
    c: &UInt64<ConstraintF>,
    d: &UInt64<ConstraintF>,
    e: &UInt64<ConstraintF>,
    ) -> Result<UInt64<ConstraintF>, SynthesisError>
    {
        // a^b^c^d^e
        // TODO: implement xor with the UInt64 gadget
        let ab = UInt64::new_witness(ark_relations::ns!(cs, "xor_5 first"), || {Ok(a.xor(b))})?;
        let abc = UInt64::new_witness(ark_relations::ns!(cs, "xor_5 second"), || {Ok(ab.xor(c))})?;
        let abcd = UInt64::new_witness(ark_relations::ns!(cs, "xor_5 third"), || {Ok(abc.xor(d))})?;
        let xor_5_result = UInt64::new_witness(ark_relations::ns!(cs, "xor_5 fourth"), || {Ok(abc.xor(e))})?;
        Ok(xor_5_result)
    }

// xor_not_and
fn xor_not_and<ConstraintF>(
        mut cs:ConstraintSystemRef<ConstraintF>,
        a: &UInt64<ConstraintF>,
        b: &UInt64<ConstraintF>,
        c: &UInt64<ConstraintF>,
    ) -> Result<UInt64<ConstraintF>, SynthesisError>
    {
        // a^((!b) & c)
        let nb = b.not(); // TODO: UInt64 gadget for NOT, AND, XOR.
        let nbc = UInt64:new_witness(ark_relations::ns!(cs,"xor_not_and second"), || {Ok(nb.and(c))})?;
        let xor_not_and_result = UInt64::new_witness(ark_relations::ns!(cs, "xor_not_and third"), || {Ok(a.xor(nbc))})?;
        Ok(xor_not_and_result)
    }

// round_1600

// keccak_f_1600

// keccak256



