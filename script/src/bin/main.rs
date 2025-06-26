//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use rand::Rng;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::{cell::RefCell, rc::Rc};
use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleHasher;
use vex_prover::{
    executor::{order_book::OrderBook, record::ExecutionTrace},
    imt::order::Order,
    prover::prove_vex,
    VexProof,
};

/// Read ELF file for the program.
pub const FIBONACCI_ELF: &[u8] = include_bytes!(
    "../../../program/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/fibonacci-program"
);

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,
}

fn generate_proof() -> VexProof<Blake2sMerkleHasher> {
    let record = Rc::new(RefCell::new(ExecutionTrace::new()));
    let mut order_book = OrderBook::new(Rc::clone(&record));
    let mut rng = rand::thread_rng();
    let mut time = 1;
    let n = 1 << 7;
    for _ in 0..n {
        let time_inc = rng.gen_range(1..=16);
        time += time_inc;
        let buy_order = Order::new(
            rng.gen_range(100000..10000000),
            rng.gen_range(1000000..=1000990),
            time,
        );
        let sell_order = Order::new(
            rng.gen_range(100000..10000000),
            rng.gen_range(1000000..=1000990),
            time,
        );
        order_book.place_buy_order(buy_order).unwrap();
        order_book.place_sell_order(sell_order).unwrap();
    }

    let mut execution_trace = std::mem::replace(&mut *record.borrow_mut(), ExecutionTrace::new());
    execution_trace.final_state = order_book.state().to_felts();
    let shape = execution_trace.sizes();
    println!("Execution trace shape: {:?}", shape);
    let start = std::time::Instant::now();
    let proof = prove_vex(execution_trace).unwrap();
    let end = start.elapsed();
    println!("Proof generated in {} ms", end.as_millis());
    proof
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let proof = generate_proof();

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&proof);

    if args.execute {
        // Execute the program
        let (mut output, report) = client.execute(FIBONACCI_ELF, &stdin).run().unwrap();
        let verified: u8 = output.read();
        if verified != 1 {
            eprintln!("Error: Program execution failed. Output: {}", verified);
        } else {
            println!("Stwo Proof verified successfully.");
        }
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
