use crate::common::*;
use ark_bls12_381::Fr;
use ark_r1cs_std::{prelude::*, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Field, SynthesisError};
use ark_std::vec::Vec;
use ark_ff::Field;

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
fn xor_2<F: Field>(mut cs: ConstraintSystemRef<F>, a: &UInt64<F>, b: &UInt64<F>) -> Result<UInt64<F>, SynthesisError>
    {
        // let xor_2 = UInt64::new_witness(ark_relations::ns!(cs, "xor_2"), || {Ok(a.xor(b))})?;
        a.xor(b)
    }

// xor_5
fn xor_5<T: ConstraintF>(
    mut cs: ConstraintSystemRef<T>,
    a: &UInt64<T>,
    b: &UInt64<T>,
    c: &UInt64<T>,
    d: &UInt64<T>,
    e: &UInt64<T>,
    ) -> Result<UInt64<T>, SynthesisError>
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
fn xor_not_and<T: ConstraintF>(
        mut cs: ConstraintSystemRef<T>,
        a: &UInt64<T>,
        b: &UInt64<T>,
        c: &UInt64<T>,
    ) -> Result<UInt64<T>, SynthesisError>
    {
        // a^((!b) & c)
        let nb = b.not(); // TODO: UInt64 gadget for NOT, AND, XOR.
        let nbc = UInt64:new_witness(ark_relations::ns!(cs,"xor_not_and second"), || {Ok(nb.and(c))})?;
        let xor_not_and_result = UInt64::new_witness(ark_relations::ns!(cs, "xor_not_and third"), || {Ok(a.xor(nbc))})?;
        Ok(xor_not_and_result)
    }

// round_1600: \theta, \rho, \pi, \chi, \iota mappings
fn round_1600<T: ConstraintF>(mut cs: ConstraintSystemRef<T>, a: &[UInt64], rc: u64) -> Result<Vec<UInt64>, SynthesisError>
{
    // TODO: implement len() method for the UInt64 gadget
    assert_eq!(a.len(), 25); 

    // # \theta step
    // A'[x][y][z] = A[x][y][z] xor CP[(x+1) mod 5][(z-1) mod 64] xor CP[(x-1) mod 5][z]
    
    // column parity vector: CP[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4], for x in 0...4 
    let mut cp = Vec::new();
    for x in 0..5{
        let cs = ark_relations::ns!(cs,format!("omega c {}",x));

        cp.push(xor_5(
            cs,
            &a[x],
            &a[x + 5usize],
            &a[x + 10usize],
            &a[x + 15usize],
            &a[x + 20usize],
        )?);
    }

    // D[x][z] = CP[(x+1) mod 5][(z-1) mod 64] xor CP[(x-1) mod 5][z]
    // => D[x] = rot(CP[x+1],1) xor C[(x-1) mod 5]
    let mut d = Vec::new();
    for x in 0..5 {
        let cs = ark_relations::ns!(cs,format!("omega d {}",x));

        d.push(xor_2(
            cs,
            &c[(x + 1usize) % 5usize].rotl(1), // TODO: implement rotl method for UInt64 gadget.
            &c[(x + 4usize) % 5usize],
        ))
    }

    // A'[x][y] = A[x][y] xor D[x]
    let mut a_new1 = Vec::new();
    for y in 0..5 {
        for x in 0..5
    }

    // # \rho step
    // A'[x][y] = A[x][y] << ROTR[x][y]
    

    // # /pi step
    // A'[y][2x + 3y] = A[x][y]

    // # \chi step
    // A'[x][y][z] = A[x][y][z] xor ((A[(x+1) mod 5][y][z] xor 1) AND A[(x+2) mod 5][y][z])

    // # \iota step
    // A'[0][0] = A[0][0] xor Round_Constant_i
}

// keccak_f_1600

// keccak256



