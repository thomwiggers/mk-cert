use kemutil::thealgorithm;
use oqs::kem::*;
use std::time::Instant;
use std::hint::black_box;

const ITERATIONS: u128 = 10000;

fn main() {
    let kemalg = Kem::new(thealgorithm).unwrap();
    let (pk, sk) = kemalg.keypair().unwrap();
    let (ct, _ss) = kemalg.encapsulate(&pk).unwrap();

    let keypair_time = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = black_box(kemalg.keypair());
        }
        Instant::now().duration_since(start).as_micros() / ITERATIONS
    };

    let encapsulate_time = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(kemalg.encapsulate(black_box(&pk)).unwrap());
        }
        Instant::now().duration_since(start).as_micros() / ITERATIONS
    };

    let decapsulate_time = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(kemalg.decapsulate(black_box(&sk), &ct).unwrap());
        }
        Instant::now().duration_since(start).as_micros() / ITERATIONS
    };

    println!(
        "{},{},{},{}",
        thealgorithm.name(),
        keypair_time,
        encapsulate_time,
        decapsulate_time,
    );
}