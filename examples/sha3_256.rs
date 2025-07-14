use ark_relations::r1cs::ConstraintSynthesizer;
use arkworks_keccak::constraints::{KeccakCircuit, KeccakMode};
use arkworks_keccak::util::{bytes_to_bitvec, sha3_256};
use clap::{Arg, Command};

fn main() {
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    let cmd = Command::new("Shake128 R1CS circuit")
        .bin_name("shake128")
        .arg(
            Arg::new("input_len_log")
                .value_name("Log2 of the test input length")
                .default_value("3")
                .value_parser(clap::value_parser!(usize))
                .long_help("Base 2 log of the test input length. For example, the value of 8 corresponds to 256 bytes of input."),
        )
        .arg(
            Arg::new("output_bytesize")
                .value_name("Log2 of the output bytesize")
                .default_value("5")
                .value_parser(clap::value_parser!(usize))
                .long_help("Base 2 log of the output bytesize. For example, the value of 5 corresponds to 32 bytes of output."),
        )
        .after_help("This command instantiates an R1CS circuit that checks that the hash of 2^(input_log_len) zero bytes matches the expected output.");

    let m = cmd.get_matches();
    let log_input_len = *m.get_one::<usize>("input_len_log").unwrap();
    let input_len = 1 << log_input_len;
    let d = 256;

    // generate preimage and expected output
    let preimage: Vec<u8> = vec![0; input_len];
    let expected = sha3_256(&preimage);

    let preimage = bytes_to_bitvec::<Fr>(&preimage);
    println!("Input length: {} bits", preimage.len());
    println!("Output length: {} bits", d);

    let circuit = KeccakCircuit {
        // public inputs
        preimage: preimage.clone(),
        expected: expected.to_vec(),
        mode: KeccakMode::Sha3_256,
        outputsize: 256,
    };

    // some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // create the circuit
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    // return the number of constraints (number of rows of the c matrix):
    let r1cs_matrices = cs.borrow().unwrap().to_matrices().unwrap();
    let num_constraints = r1cs_matrices.c.len();
    println!("Number of constraints: {}", num_constraints);

    // check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    if !is_satisfied {
        // if it isn't, find out the offending constraint.
        println!("Unsatisfied constraint: {:?}\n", cs.which_is_unsatisfied());
        assert!(is_satisfied);
    }

    println!("All constraints satisfied!");
}
