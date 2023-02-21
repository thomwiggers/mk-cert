use std::hint::black_box;
use std::time::Instant;

use oqs::sig::*;

use signutil::alg;

const ITERATIONS: u128 = 100;

fn main() -> std::io::Result<()> {
    let sigalg = Sig::new(alg).unwrap();
    assert!(alg.is_enabled());
    let (pk, sk) = sigalg.keypair().unwrap();
    let message = [0u8; 64];
    let signature = sigalg.sign(&message, &sk).unwrap();
    sigalg.verify(&message, &signature, &pk).unwrap();

    let keypair_time = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = black_box(sigalg.keypair());
        }
        Instant::now().duration_since(start).as_micros() / ITERATIONS
    };

    let signing_time = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(sigalg.sign(black_box(&message), &sk)).unwrap();
        }
        Instant::now().duration_since(start).as_micros() / ITERATIONS
    };
    let verify_time = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = black_box(sigalg.verify(black_box(&message), black_box(&signature), &pk));
        }

        Instant::now().duration_since(start).as_micros() / ITERATIONS
    };
    println!(
        "{},{},{},{}",
        alg.name(),
        keypair_time,
        signing_time,
        verify_time
    );
    Ok(())
}
