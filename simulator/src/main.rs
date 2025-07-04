// Licensed under the Apache-2.0 license

#[cfg(not(feature = "rustcrypto"))]
compile_error!("must provide a crypto implementation");

use clap::Parser;
use dpe::DpeFlags;
use log::{error, info, trace, warn};
use platform::default::{DefaultPlatform, DefaultPlatformProfile};
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;

use dpe::{
    dpe_instance::{DpeEnv, DpeTypes},
    response::Response,
    support::Support,
    DpeInstance,
};

#[cfg(feature = "dpe_profile_p256_sha256")]
use crypto::Ecdsa256RustCrypto;

#[cfg(feature = "dpe_profile_p384_sha384")]
use crypto::Ecdsa384RustCrypto;

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
    if let Ok(command) = dpe.deserialize_command(cmd) {
        trace!("| Locality `{locality:#x}` requested {command:x?}",);
    } else {
        trace!("| Locality `{locality:#010x}` requested invalid command. {cmd:02x?}")
    }
    trace!("|");

    let response = dpe.execute_serialized_command(env, locality, cmd).unwrap();

    let response_code = match response {
        Response::GetProfile(ref res) => res.resp_hdr.status,
        Response::InitCtx(ref res) => res.resp_hdr.status,
        Response::DeriveContext(ref res) => res.resp_hdr.status,
        Response::DeriveContextExportedCdi(ref res) => res.resp_hdr.status,
        Response::RotateCtx(ref res) => res.resp_hdr.status,
        Response::CertifyKey(ref res) => res.resp_hdr.status,
        Response::Sign(ref res) => res.resp_hdr.status,
        Response::DestroyCtx(ref resp_hdr) => resp_hdr.status,
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

    /// Supports the RECURSIVE extension to DeriveContext.
    #[arg(long)]
    supports_recursive: bool,

    /// Automatically initializes the default context.
    #[arg(long)]
    supports_auto_init: bool,

    /// Supports the RotateContextHandle command.
    #[arg(long)]
    supports_rotate_context: bool,

    /// Supports the X509 CertifyKey format.
    #[arg(long)]
    supports_x509: bool,

    /// Supports the CSR CertifyKey format.
    #[arg(long)]
    supports_csr: bool,

    /// Supports the INTERNAL_INPUT_INFO extension to DeriveContext
    #[arg(long)]
    supports_internal_info: bool,

    /// Supports the INTERNAL_INPUT_DICE extension to DeriveContext
    #[arg(long)]
    supports_internal_dice: bool,

    /// Supports the RETAIN_PARENT_CONTEXT extension to DeriveContext
    #[arg(long)]
    supports_retain_parent_context: bool,

    /// Supports the CDI_EXPORT extension to DeriveContext
    #[arg(long)]
    supports_cdi_export: bool,

    /// Mark DICE extensions as critical
    #[arg(long)]
    mark_dice_extensions_critical: bool,
}

struct SimTypes {}

impl DpeTypes for SimTypes {
    #[cfg(feature = "dpe_profile_p256_sha256")]
    type Crypto<'a> = Ecdsa256RustCrypto;

    #[cfg(feature = "dpe_profile_p384_sha384")]
    type Crypto<'a> = Ecdsa384RustCrypto;

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
    support.set(Support::RECURSIVE, args.supports_recursive);
    support.set(Support::ROTATE_CONTEXT, args.supports_rotate_context);
    support.set(Support::INTERNAL_DICE, args.supports_internal_dice);
    support.set(Support::INTERNAL_INFO, args.supports_internal_info);
    support.set(
        Support::RETAIN_PARENT_CONTEXT,
        args.supports_retain_parent_context,
    );
    support.set(Support::CDI_EXPORT, args.supports_cdi_export);

    let mut flags = DpeFlags::empty();
    flags.set(
        DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL,
        args.mark_dice_extensions_critical,
    );

    #[cfg(feature = "dpe_profile_p256_sha256")]
    let p = DefaultPlatformProfile::P256;
    #[cfg(feature = "dpe_profile_p384_sha384")]
    let p = DefaultPlatformProfile::P384;
    let mut env = DpeEnv::<SimTypes> {
        crypto: <SimTypes as DpeTypes>::Crypto::new(),
        platform: DefaultPlatform(p),
        state: &mut dpe::State::new(support, flags),
    };
    let mut dpe = DpeInstance::new(&mut env).map_err(|err| {
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
