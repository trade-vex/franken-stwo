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
    constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator},
    fields::{qm31::SecureField, FieldExpOps},
    pcs::{CommitmentSchemeVerifier, PcsConfig},
    vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher},
    verify, StarkProof,
};
sp1_zkvm::entrypoint!(main);

#[derive(Clone)]
pub struct WideFibonacciEval<const N: usize> {
    pub log_n_rows: u32,
}

impl<const N: usize> FrameworkEval for WideFibonacciEval<N> {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut a = eval.next_trace_mask();
        let mut b = eval.next_trace_mask();
        for _ in 2..N {
            let c = eval.next_trace_mask();
            eval.add_constraint(c.clone() - (a.square() + b.square()));
            a = b;
            b = c;
        }
        eval
    }
}

pub fn main() {
    let log_n_instances: u32 = sp1_zkvm::io::read();
    let proof: StarkProof<Blake2sMerkleHasher> = sp1_zkvm::io::read();

    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let mut location_allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut location_allocator,
        WideFibonacciEval::<100> {
            log_n_rows: log_n_instances,
        },
        SecureField::zero(),
    );
    let sizes = component.trace_log_degree_bounds();

    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    let result = verify(&[&component], verifier_channel, commitment_scheme, proof);
    sp1_zkvm::io::commit(if result.is_ok() { &1_u8 } else { &0 });
}
