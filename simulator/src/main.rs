use clap::Parser;
use crypto::OpensslCrypto;
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;

use dpe::{
    commands::Command,
    dpe_instance::{DpeInstance, Support},
    execute_command,
};

const SOCKET_PATH: &str = "/tmp/dpe-sim.socket";

fn handle_request(dpe: &mut DpeInstance<OpensslCrypto>, stream: &mut UnixStream) {
    let mut buf = [0u8; 128];
    let (locality, cmd) = {
        let len = stream.read(&mut buf).unwrap();
        (
            u32::from_le_bytes(buf[..4].try_into().unwrap()),
            &buf[4..len],
        )
    };

    println!("----------------------------------");
    if let Ok(command) = Command::deserialize(cmd) {
        println!("| Locality `{locality:#x}` requested {command:x?}",);
    } else {
        println!("| Locality `{locality:#010x}` requested invalid command. {cmd:02x?}")
    }
    println!("|");

    let mut response = [0u8; 128];
    let len = execute_command(dpe, locality, cmd, &mut response).unwrap();

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
    const LOCALITIES: [u32; 2] = [
        DpeInstance::<OpensslCrypto>::AUTO_INIT_LOCALITY,
        u32::from_be_bytes(*b"OTHR"),
    ];
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
    let mut dpe = DpeInstance::<OpensslCrypto>::new(support, &LOCALITIES).map_err(|err| {
        Error::new(
            ErrorKind::Other,
            format!("{err:?} while creating new DPE instance"),
        )
    })?;

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
