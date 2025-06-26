//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

use stwo_verifier_no_std::vcs::blake2_merkle::Blake2sMerkleHasher;
use stwo_verifier_no_std::vex::{verify_vex, VexProof};
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // let log_n_instances: u32 = sp1_zkvm::io::read();
    let proof: VexProof<Blake2sMerkleHasher> = sp1_zkvm::io::read();

    let result = verify_vex(proof);
    sp1_zkvm::io::commit(if result.is_ok() { &1_u8 } else { &0 });
}
