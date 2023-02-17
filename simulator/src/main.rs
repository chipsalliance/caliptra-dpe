use ctrlc;
use dpe::commands::{CommandHdr, DpeInstance};
use std::fs;
use std::io::Read;
use std::mem;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;

const SOCKET_PATH: &str = "/tmp/dpe-sim.socket";

fn handle_request(_dpe: &mut DpeInstance, stream: &mut UnixStream) {
    let mut hdr_buf = [0u8; mem::size_of::<CommandHdr>()];
    let mut _size = match stream.read_exact(&mut hdr_buf) {
        Ok(size) => size,
        Err(_) => {
            println!("Failed to read command header");
            return;
        }
    };

    let (_, hdr, _) = unsafe { hdr_buf.align_to::<CommandHdr>() };

    println!("Got command {:#x}", hdr[0].cmd_id);
}

fn cleanup() {
    match fs::remove_file(SOCKET_PATH) {
        Ok(_) => {
            println!();
        },
        Err(_) => {
            println!("Warning: Unable to unlink {}", SOCKET_PATH);
        }
    }
}

fn main() -> std::io::Result<()> {
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

    let mut dpe = DpeInstance::new();

    println!("DPE listening to socket {}", SOCKET_PATH);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                handle_request(&mut dpe, &mut stream);
            }
            Err(err) => {
                println!("Failed to open socket: {}", err);
                cleanup();
                break;
            }
        }
    }

    Ok(())
}
