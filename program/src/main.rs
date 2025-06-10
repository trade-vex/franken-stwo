//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

use num_traits::Zero;
use stwo_verifier_no_std::{
    air::Component,
    channel::Blake2sChannel,
    constraint_framework::{FrameworkComponent, TraceLocationAllocator},
    examples::WideFibonacciEval,
    fields::qm31::SecureField,
    pcs::{CommitmentSchemeVerifier, PcsConfig},
    vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    verify, StarkProof,
};
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let proof_serialized = sp1_zkvm::io::read_vec();
    let proof: StarkProof<Blake2sMerkleHasher> = serde_json::from_slice(&proof_serialized).unwrap();
    let eval_serialized = sp1_zkvm::io::read_vec();
    let eval: WideFibonacciEval<100> = serde_json::from_slice(&eval_serialized).unwrap();
    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let mut location_allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut location_allocator, eval, SecureField::zero());
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    let result = verify(&[&component], verifier_channel, commitment_scheme, proof);
    sp1_zkvm::io::commit(if result.is_ok() { &1_u8 } else { &0 });
}
