use std::io::prelude::*;
use std::fs::File;

mod instance;
use instance::csidh;



fn main() -> std::io::Result<()> {
    let (pk, sk) = csidh::keygen();

    let mut pubkeyfile = File::create("publickey.bin")?;
    let mut seckeyfile = File::create("secretkey.bin")?;

    pubkeyfile.write_all(pk.as_ref())?;
    seckeyfile.write_all(sk.as_ref())?;

    Ok(())
}

