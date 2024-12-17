use clap::Parser;
use anyhow::{Result, bail};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;

/// Unlock Some Binary
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, author)]
struct Args {
}

const ENCRYPTED: [u8; 46] = [0x77,0x59,0xf5,0x4,0xd5,0x61,0xd1,0xe7,0x84,0x51,0xb2,0xec,0xf5,0x1a,0x27,0x2c,0x1,0x7d,0x89,0xa7,0xad,0xa5,0xc6,0x58,0x9f,0xf3,0xf5,0x8a,0xc9,0x43,0x27,0x1,0x7a,0x13,0xb,0xc9,0xe5,0x2,0xc0,0x6,0x29,0x81,0xa7,0x42,0x43,0xe9];

fn try_decrypt(vidpid: u32) -> Option<Vec<u8>> {
    let nonce = Nonce::default();
    let key_bytes: Vec<u8> = (0..8).into_iter().map(|_| vidpid.to_be_bytes()).flatten().collect();
    let key: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    cipher.decrypt(&nonce, &ENCRYPTED[..]).ok()
}

fn main() -> Result<()>{
    let args = Args::parse();

    for device in rusb::devices()?.iter() {
        let device_desc = device.device_descriptor()?;
        if device_desc.vendor_id() != 0x8086 {
            continue;
        }
        let vidpid = ((device_desc.vendor_id() as u32) << 16) | device_desc.product_id() as u32;
        if let Some(cleartext) = try_decrypt(vidpid) {
            println!("{}", String::from_utf8(cleartext)?);
            return Ok(());
        }
    }
    bail!("Missing beefy intel key.");
}
