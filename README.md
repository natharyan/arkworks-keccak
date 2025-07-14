# Arkworks-Keccak

This repository provides R1CS circuits for the Keccak family of hash functions, specifically:

- **SHA3-256**
- **SHAKE128**
- **SHAKE256**

## Directory overview

The directory structure is as follows:

- `examples/`: code to run examples for SHA3-256 and the two XOFs.
- `constraints.rs`: code for creating R1CS circuits for the Keccak sponge construction and permutation function.
- `utils.rs`: utility functions for bitwise operations on UInt64 variables and creating public inputs.

## Running the examples

Run the following commands:

```bash
cargo build --release
cargo run -r --example shake128 6 100
```

In the above case, the input message will be $2^6$ zero bytes and output size will be of size 100 bytes. The output will look like the following:

```
Input length: 512 bits
Output length: 800 bits
Expected hash: "fc37fe19d48ad68ba1f793aa126f5f14178a89b6dfb87443ef655b9819c52121bb164c3728cb96d54ffec73497d99cc6a1d85975bd264aab5924246e0b5cd026a743f75bc822b558cb1f6a8e151e4b1b7ecf3c2a64739895246a0a2e638c21c66c13ba60"
Actual hash: "fc37fe19d48ad68ba1f793aa126f5f14178a89b6dfb87443ef655b9819c52121bb164c3728cb96d54ffec73497d99cc6a1d85975bd264aab5924246e0b5cd026a743f75bc822b558cb1f6a8e151e4b1b7ecf3c2a64739895246a0a2e638c21c66c13ba60"
Number of constraints: 153536
All constraints satisfied!
```

## License

Licensed under either of

- Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT) at your option.

