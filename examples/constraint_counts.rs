use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use arkworks_keccak::constraints::{KeccakCircuit, KeccakMode};
use arkworks_keccak::util::{sha3_256, shake_128, shake_256};

fn main() {
    println!("                        # instance variables |      # witness |    #constraints |");
    
    // Test with different input sizes
    for log_input_len in [3, 4, 5, 6, 7, 8] {
        let input_len = 1 << log_input_len;
        println!("\nInput size: {} bytes", input_len);
        println!("--------------------------------------------------------------------------------");
        count_sha3_256_constraints(input_len);
        count_shake128_constraints(input_len, 256);
        count_shake256_constraints(input_len, 256);
    }
}

fn count_sha3_256_constraints(input_len: usize) {
    let preimage: Vec<u8> = vec![0; input_len];
    let expected = sha3_256(&preimage);

    let preimage_bits: Vec<bool> = preimage
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        .collect();

    let circuit = KeccakCircuit {
        preimage: preimage_bits,
        expected: expected.to_vec(),
        mode: KeccakMode::Sha3_256,
        outputsize: 256,
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    println!(
        "SHA3-256:                          {:8} |       {:8} |        {:8} |",
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
    );

    assert!(cs.is_satisfied().unwrap());
}

fn count_shake128_constraints(input_len: usize, output_bits: usize) {
    let preimage: Vec<u8> = vec![0; input_len];
    let expected = shake_128(&preimage, output_bits / 8);

    let preimage_bits: Vec<bool> = preimage
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        .collect();

    let circuit = KeccakCircuit {
        preimage: preimage_bits,
        expected: expected.to_vec(),
        mode: KeccakMode::Shake128,
        outputsize: output_bits,
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    println!(
        "SHAKE128 ({}-bit output):         {:8} |       {:8} |        {:8} |",
        output_bits,
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
    );

    assert!(cs.is_satisfied().unwrap());
}

fn count_shake256_constraints(input_len: usize, output_bits: usize) {
    let preimage: Vec<u8> = vec![0; input_len];
    let expected = shake_256(&preimage, output_bits / 8);

    let preimage_bits: Vec<bool> = preimage
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        .collect();

    let circuit = KeccakCircuit {
        preimage: preimage_bits,
        expected: expected.to_vec(),
        mode: KeccakMode::Shake256,
        outputsize: output_bits,
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    println!(
        "SHAKE256 ({}-bit output):         {:8} |       {:8} |        {:8} |",
        output_bits,
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
    );

    assert!(cs.is_satisfied().unwrap());
}