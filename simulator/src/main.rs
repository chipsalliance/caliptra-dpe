// Licensed under the Apache-2.0 license

use clap::Parser;
use crypto::OpensslCrypto;
use log::{error, info, trace, warn};
use platform::DefaultPlatform;
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;

use dpe::{
    commands::Command,
    dpe_instance::{DpeEnv, DpeTypes},
    response::Response,
    support::Support,
    DpeInstance,
};

const SOCKET_PATH: &str = "/tmp/dpe-sim.socket";

fn handle_request(dpe: &mut DpeInstance, env: &mut DpeEnv<impl DpeTypes>, stream: &mut UnixStream) {
    let mut buf = [0u8; 4096];
    let (locality, cmd) = {
        let len = stream.read(&mut buf).unwrap();
        (
            u32::from_le_bytes(buf[..4].try_into().unwrap()),
            &buf[4..len],
        )
    };

    trace!("----------------------------------");
    if let Ok(command) = Command::deserialize(cmd) {
        trace!("| Locality `{locality:#x}` requested {command:x?}",);
    } else {
        trace!("| Locality `{locality:#010x}` requested invalid command. {cmd:02x?}")
    }
    trace!("|");

    let response = dpe.execute_serialized_command(env, locality, cmd).unwrap();

    let response_code = match response {
        Response::GetProfile(ref res) => res.resp_hdr.status,
        Response::InitCtx(ref res) => res.resp_hdr.status,
        Response::DeriveChild(ref res) => res.resp_hdr.status,
        Response::RotateCtx(ref res) => res.resp_hdr.status,
        Response::CertifyKey(ref res) => res.resp_hdr.status,
        Response::Sign(ref res) => res.resp_hdr.status,
        Response::DestroyCtx(ref resp_hdr) => resp_hdr.status,
        Response::ExtendTci(ref res) => res.resp_hdr.status,
        Response::TagTci(ref res) => res.resp_hdr.status,
        Response::GetTaggedTci(ref res) => res.resp_hdr.status,
        Response::GetCertificateChain(ref res) => res.resp_hdr.status,
        Response::Error(ref resp_hdr) => resp_hdr.status,
    };
    // There are a few vendor error codes starting at 0x1000, so this can be a 2 bytes.
    trace!("| Response Code {response_code:#06x}");
    trace!("----------------------------------");

    stream.write_all(response.as_bytes()).unwrap();
}

fn cleanup() {
    if let Err(e) = fs::remove_file(SOCKET_PATH) {
        warn!("Unable to unlink {SOCKET_PATH}: {e}");
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

    /// Supports the X509 CertifyKey format.
    #[arg(long)]
    supports_x509: bool,

    /// Supports the CSR CertifyKey format.
    #[arg(long)]
    supports_csr: bool,

    // Supports the CertifyKey IS_CA flag
    #[arg(long)]
    supports_is_ca: bool,

    /// Supports symmetric derivation.
    #[arg(long)]
    supports_is_symmetric: bool,

    /// Supports the INTERNAL_INPUT_INFO extension to DeriveChild
    #[arg(long)]
    supports_internal_info: bool,

    /// Supports the INTERNAL_INPUT_DICE extension to DeriveChild
    #[arg(long)]
    supports_internal_dice: bool,
}

struct SimTypes {}

impl DpeTypes for SimTypes {
    type Crypto<'a> = OpensslCrypto;
    type Platform<'a> = DefaultPlatform;
}

fn main() -> std::io::Result<()> {
    env_logger::init();
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

    let mut support = Support::default();
    support.set(Support::SIMULATION, args.supports_simulation);
    support.set(Support::AUTO_INIT, args.supports_auto_init);
    support.set(Support::X509, args.supports_x509);
    support.set(Support::CSR, args.supports_csr);
    support.set(Support::EXTEND_TCI, args.supports_extend_tci);
    support.set(Support::ROTATE_CONTEXT, args.supports_rotate_context);
    support.set(Support::INTERNAL_DICE, args.supports_internal_dice);
    support.set(Support::INTERNAL_INFO, args.supports_internal_info);
    support.set(Support::IS_CA, args.supports_is_ca);
    support.set(Support::IS_SYMMETRIC, args.supports_is_symmetric);
    support.set(Support::TAGGING, args.supports_tagging);

    let mut env = DpeEnv::<SimTypes> {
        crypto: OpensslCrypto::new(),
        platform: DefaultPlatform,
    };

    let mut dpe = DpeInstance::new(&mut env, support).map_err(|err| {
        Error::new(
            ErrorKind::Other,
            format!("{err:?} while creating new DPE instance"),
        )
    })?;

    info!("DPE listening to socket {SOCKET_PATH}");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                handle_request(&mut dpe, &mut env, &mut stream);
            }
            Err(err) => {
                error!("Failed to open socket: {err}");
                cleanup();
                break;
            }
        }
    }

    Ok(())
}
