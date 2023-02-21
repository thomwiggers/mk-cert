use csidhutil::csidh;
use std::time::Instant;
use std::hint::black_box;

const ITERATIONS: u128 = 100;

fn main() {
    let (_pk, sk) = csidh::keygen();
    let (pk2, _) = csidh::keygen();

    let keypair_time = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = black_box(csidh::keygen());
        }
        Instant::now().duration_since(start).as_micros() / ITERATIONS
    };

    let derive_time = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(csidh::derive(&pk2, black_box(&sk)));
        }
        Instant::now().duration_since(start).as_micros() / ITERATIONS
    };


    println!(
        "{},{},{}",
        csidh::name(),
        keypair_time,
        derive_time,
    );
}