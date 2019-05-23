use std::fs::File;
use std::io::prelude::*;

use pqcrypto::prelude::*;
mod kem;
use kem::*;


fn main() -> std::io::Result<()> {
    let (pk, sk) = keypair();

    let mut pubkeyfile = File::create("kempublic.key")?;
    let mut seckeyfile = File::create("kemsecret.key")?;

    pubkeyfile.write_all(pk.as_bytes())?;
    seckeyfile.write_all(sk.as_bytes())?;

    Ok(())
}
