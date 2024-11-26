use clap::Parser;
use anyhow::{Context, Result, bail};

/// Unlock Some Binary
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, author)]
struct Args {
    /// The unlock password
    #[arg(short, long)]
    password: String,
}

fn try_unlock(pw: u32, vidpid: u32) -> bool {
    pw ^ vidpid == 0x1e528ddc
}

fn main() -> Result<()>{
    let args = Args::parse();
    let password = args.password.parse::<u32>().context("Invalid password")?;

    for device in rusb::devices()?.iter() {
        let device_desc = device.device_descriptor()?;
        let vidpid = ((device_desc.vendor_id() as u32) << 16) | device_desc.product_id() as u32;
        if try_unlock(password, vidpid) {
            println!("flag{{{:8x}_and_coffee}}", 0xc0ff3333^password^vidpid);
            return Ok(());
        }
    }
    bail!("Nope.");
}
