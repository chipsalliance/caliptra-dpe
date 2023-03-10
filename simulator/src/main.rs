use clap::Parser;
use dpe::commands::Command;
use dpe::crypto::Crypto;
use dpe::dpe_instance::{DpeInstance, Support};
use dpe::response::DpeErrorCode;
use dpe::{execute_command, DpeProfile};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;

const SOCKET_PATH: &str = "/tmp/dpe-sim.socket";

fn handle_request(dpe: &mut DpeInstance, stream: &mut UnixStream) {
    let mut buf = [0u8; 128];
    let len = stream.read(&mut buf).unwrap();

    println!("----------------------------------");
    if let Ok(command) = Command::deserialize(&buf[..len]) {
        println!("| {command:x?}",);
    } else {
        println!("| Received invalid command. {:02x?}", &buf[..len])
    }
    println!("|");

    let mut response = [0u8; 128];
    let len = execute_command::<OpensslCrypto>(dpe, &buf[..len], &mut response).unwrap();

    let response_code = u32::from_le_bytes(response[4..8].try_into().unwrap());
    // There are a few vendor error codes starting at 0x1000, so this can be a 2 bytes.
    println!("| Response Code {response_code:#06x}");
    println!("----------------------------------");

    stream.write_all(&response[..len]).unwrap();
}

fn cleanup() {
    match fs::remove_file(SOCKET_PATH) {
        Ok(_) => {
            println!();
        }
        Err(_) => {
            println!("Warning: Unable to unlink {SOCKET_PATH}");
        }
    }
}

/// Starts a DPE simulator that will receive commands and send responses over unix streams.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Supports simulation contexts.
    #[arg(long)]
    supports_simulation: bool,

    /// Supports the ExtendTci command.
    #[arg(long)]
    supports_extend_tci: bool,

    /// Automatically initializes the default context.
    #[arg(long)]
    supports_auto_init: bool,

    /// Supports the TagTci and GetTaggedTci commands.
    #[arg(long)]
    supports_tagging: bool,

    /// Supports the RotateContextHandle command.
    #[arg(long)]
    supports_rotate_context: bool,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let socket = Path::new(SOCKET_PATH);
    // Delete old socket if necessary
    if socket.exists() {
        cleanup();
    }

    let listener = UnixListener::bind(socket)?;

    ctrlc::set_handler(move || {
        cleanup();
        process::exit(0);
    })
    .unwrap();

    let support = Support {
        simulation: args.supports_simulation,
        extend_tci: args.supports_extend_tci,
        auto_init: args.supports_auto_init,
        tagging: args.supports_tagging,
        rotate_context: args.supports_rotate_context,
    };
    let mut dpe = DpeInstance::new::<OpensslCrypto>(support);

    println!("DPE listening to socket {SOCKET_PATH}");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                handle_request(&mut dpe, &mut stream);
            }
            Err(err) => {
                println!("Failed to open socket: {err}");
                cleanup();
                break;
            }
        }
    }

    Ok(())
}

struct OpensslCrypto;

impl Crypto for OpensslCrypto {
    fn rand_bytes(dst: &mut [u8]) -> Result<(), DpeErrorCode> {
        openssl::rand::rand_bytes(dst).map_err(|_| DpeErrorCode::InternalError)
    }

    fn _hash(profile: DpeProfile, bytes: &[u8], digest: &mut [u8]) -> Result<(), DpeErrorCode> {
        use openssl::hash::{hash, MessageDigest};
        let alg = match profile {
            DpeProfile::P256Sha256 => MessageDigest::sha256(),
            DpeProfile::P384Sha384 => MessageDigest::sha384(),
        };
        digest.copy_from_slice(&hash(alg, bytes).map_err(|_| DpeErrorCode::InternalError)?);
        Ok(())
    }
}
