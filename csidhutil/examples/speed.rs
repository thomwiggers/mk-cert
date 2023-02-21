use csidhutil::csidh;
use std::time::Instant;
use std::hint::black_box;

fn main() {
    let iterations: u128 = match env::var("ITERATIONS") {
        Ok(val) => val.parse::<u128>().unwrap(),
        Err(_) => 1000,
    };

    let (_pk, sk) = csidh::keygen();
    let (pk2, _) = csidh::keygen();

    let keypair_time = {
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = black_box(csidh::keygen());
        }
        Instant::now().duration_since(start).as_micros() / iterations
    };

    let derive_time = {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(csidh::derive(&pk2, black_box(&sk)));
        }
        Instant::now().duration_since(start).as_micros() / iterations
    };


    println!(
        "{},{},{}",
        csidh::name(),
        keypair_time,
        derive_time,
    );
}