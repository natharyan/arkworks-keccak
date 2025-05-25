use crate::*;
use ark_ff::Field;
use ark_r1cs_std::{boolean::Boolean, prelude::*, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use proptest::proptest;

// round constants for the \iota mapping, n_r = 24
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
fn xor_2<F: Field>(a: &UInt64<F>, b: &UInt64<F>) -> Result<UInt64<F>, SynthesisError> {
    a.xor(&b)
}

// xor_5
fn xor_5<F: Field>(
    a: &UInt64<F>,
    b: &UInt64<F>,
    c: &UInt64<F>,
    d: &UInt64<F>,
    e: &UInt64<F>,
) -> Result<UInt64<F>, SynthesisError> {
    // a^b^c^d^e
    let ab = a.xor(&b)?;
    let abc = ab.xor(&c)?;
    let abcd = abc.xor(&d)?;
    let result = abcd.xor(&e)?;
    Ok(result)
}

// xor_not_and
fn xor_not_and<F: Field>(
    a: &UInt64<F>,
    b: &UInt64<F>,
    c: &UInt64<F>,
) -> Result<UInt64<F>, SynthesisError> {
    // a^((!b) & c)
    let neqb = not(&b)?;
    let nbc = and(&neqb, &c)?;
    a.xor(&nbc)
}

// round_1600: \theta, \rho, \pi, \chi, \iota mappings
fn round_1600<F: Field>(
    _cs: ConstraintSystemRef<F>,
    a: &[UInt64<F>],
    rc: u64,
) -> Result<Vec<UInt64<F>>, SynthesisError> {
    assert_eq!(a.len(), 25);

    // # \theta step
    // A'[x][y][z] = A[x][y][z] xor CP[(x+1) mod 5][(z-1) mod 64] xor CP[(x-1) mod 5][z]

    // column parity vector: CP[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4], for x in 0...4
    let mut cp = Vec::new();
    for x in 0..5 {
        cp.push(xor_5(
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
        d.push(xor_2(
            &rotl(&cp[(x + 1usize) % 5usize], 1)?,
            &cp[(x + 4usize) % 5usize],
        )?)
    }

    // A'[x][y] = A[x][y] xor D[x]
    let mut a_new1 = Vec::new();
    for y in 0..5 {
        for x in 0..5 {
            a_new1.push(xor_2(&a[x + (y * 5usize)], &d[x])?);
        }
    }

    // # \rho step
    // A'[x][y] = A[x][y] << ROTR[x][y]
    // # /pi step
    // A'[y][2x + 3y] = A[x][y]
    let mut b = a_new1.clone();
    for y in 0..5 {
        for x in 0..5 {
            b[y + ((((2 * x) + (3 * y)) % 5) * 5usize)] =
                rotl(&a_new1[x + (y * 5usize)], ROTR[x + (y * 5usize)])?;
        }
    }

    // # \chi step
    // A'[x][y][z] = A[x][y][z] xor ((A[(x+1) mod 5][y][z] xor 1) AND A[(x+2) mod 5][y][z])
    let mut a_new2 = Vec::new();
    for y in 0..5 {
        for x in 0..5 {
            a_new2.push(xor_not_and(
                &b[x + (y * 5usize)],
                &b[((x + 1usize) % 5usize) + (y * 5usize)],
                &b[((x + 2usize) % 5usize) + (y * 5usize)],
            )?);
        }
    }

    // # \iota step
    // A'[0][0] = A[0][0] xor Round_Constant_i
    let rc = UInt64::constant(rc);
    a_new2[0] = a_new2[0].xor(&rc)?;
    Ok(a_new2)
}

// keccak_f_1600
fn keccak_f_1600<F: Field>(
    cs: ConstraintSystemRef<F>,
    input: &[Boolean<F>],
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    // b bit string as input
    assert_eq!(input.len(), 1600);

    // create flattened state array
    let mut a = input
        .chunks(64)
        .map(|chunk| UInt64::from_bits_le(chunk))
        .collect::<Vec<UInt64<F>>>(); // (x,y) -> (i%5,i/5)

    for (_i, round_constant) in ROUND_CONSTANTS.iter().enumerate() {
        a = round_1600(cs.clone(), &a, *round_constant)?;
    }

    let a_new = a.into_iter().flat_map(|e| e.to_bits_le()).collect();

    Ok(a_new)
}
// keccak256
pub fn keccak256_gadget<F: Field>(
    cs: ConstraintSystemRef<F>,
    input: &[Boolean<F>],
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    assert_eq!(input.len(), 512);
    let mut m = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for i in 0..1600 {
        if i < 512 {
            m.push(input[i].clone());
        } else {
            m.push(Boolean::Constant(false));
        }
    }

    // # Padding
    // d = 2^|Mbits| + sum for i=0..|Mbits|-1 of 2^i*Mbits[i]
    // P = Mbytes || d || 0x00 || … || 0x00
    // P = P xor (0x00 || … || 0x00 || 0x80)
    //0x0100 ... 0080
    m[512] = Boolean::Constant(true);
    m[1087] = Boolean::Constant(true); // r = 1088, r+c = 1600

    // # Initialization
    // S[x,y] = 0,                               for (x,y) in (0…4,0…4)

    // # Absorbing phase
    // for each block Pi in P
    //   S[x,y] = S[x,y] xor Pi[x+5*y],          for (x,y) such that x+5*y < r/w
    //   S = Keccak-f[r+c](S)

    let state = keccak_f_1600(cs, &m)?; // m = r in keccak256, so a single block (m_1) is produced after padding

    //# Squeezing phase
    // Z = empty string
    let mut z = Vec::new();

    // while output is requested
    // Z = Z || S[x,y]
    // S = Keccak-f[r + c](S)
    for item in state[..256].iter() {
        // n = 0.r + 256
        z.push(item.clone());
    }

    Ok(z)
}

pub struct KeccakCircuit<F: Field> {
    pub preimage: Vec<Boolean<F>>, // 512 bools
    pub expected: [u8; 32],        // 32 bytes == 256 bits
}

impl<F: Field> ConstraintSynthesizer<F> for KeccakCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let preimage = vec_to_public_input(cs.clone(), "preimage", self.preimage)?;
        let expected = bytes_to_bitvec::<F>(&self.expected);
        let expected = vec_to_public_input(cs.clone(), "expected", expected)?;
        let result = keccak256_gadget(cs.clone(), &preimage)?;

        for (o, e) in result.iter().zip(expected.iter()) {
            o.enforce_equal(e)?;
        }

        Ok(())
    }
}

proptest! {
    #[test]
    fn test_keccak256(preimage in "[0-9a-f]{128}"){
        use ark_relations::r1cs::{ConstraintLayer,ConstraintSystem,TracingMode};
        use tracing_subscriber::Registry;
        use tracing_subscriber::layer::SubscriberExt;
        use ark_bls12_381::Fr;

        let preimage = hex::decode(preimage).unwrap();
        let expected = keccak256(&preimage);

        let preimage = bytes_to_bitvec::<Fr>(&preimage);

        let circuit = KeccakCircuit {
            // public inputs
            preimage: preimage.clone(),
            expected: expected.clone(),
        };

        // some boilerplate that helps with debugging
        let mut layer = ConstraintLayer::default();
        layer.mode = TracingMode::OnlyConstraints;
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // next, let's make the circuit
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        // let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied{
            // if it isn't, find out the offending constraint.
            println!("Unsatisfied constraint: {:?}\n", cs.which_is_unsatisfied());
        }
        assert!(is_satisfied);
    }
}
