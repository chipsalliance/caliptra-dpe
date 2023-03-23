use clap::Parser;
use dpe::crypto::Hasher;
use ossl_crypto::{OpensslCrypto, OpensslHasher};
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;

use openssl::{hash::MessageDigest, nid::Nid};

use dpe::{
    commands::Command,
    crypto::{Crypto, EcdsaPub, EcdsaSignature},
    dpe_instance::{DpeInstance, Support},
    execute_command,
    response::DpeErrorCode,
    DpeProfile,
};

const SOCKET_PATH: &str = "/tmp/dpe-sim.socket";

fn handle_request(dpe: &mut DpeInstance<SimCrypto>, stream: &mut UnixStream) {
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
        DpeInstance::<SimCrypto>::AUTO_INIT_LOCALITY,
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
    let mut dpe = DpeInstance::<SimCrypto>::new(support, &LOCALITIES).map_err(|err| {
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

pub struct SimHasher(ossl_crypto::OpensslHasher);

impl Hasher for SimHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), DpeErrorCode> {
        self.0
            .update(bytes)
            .map_err(|_| DpeErrorCode::InternalError)
    }

    fn finish(self, digest: &mut [u8]) -> Result<(), DpeErrorCode> {
        self.0
            .finish(digest)
            .map_err(|_| DpeErrorCode::InternalError)
    }
}

struct SimCrypto;

impl SimCrypto {
    fn get_digest(profile: &DpeProfile) -> MessageDigest {
        match profile {
            DpeProfile::P256Sha256 => MessageDigest::sha256(),
            DpeProfile::P384Sha384 => MessageDigest::sha384(),
        }
    }

    fn get_curve(profile: &DpeProfile) -> Nid {
        match profile {
            DpeProfile::P256Sha256 => Nid::X9_62_PRIME256V1,
            DpeProfile::P384Sha384 => Nid::SECP384R1,
        }
    }
}

impl Crypto for SimCrypto {
    type Cdi = Vec<u8>;
    type Hasher = SimHasher;

    /// Uses incrementing values for each byte to ensure tests are
    /// deterministic
    fn rand_bytes(dst: &mut [u8]) -> Result<(), DpeErrorCode> {
        OpensslCrypto::rand_bytes(dst).map_err(|_| DpeErrorCode::InternalError)
    }

    fn hash_initialize(profile: DpeProfile) -> Result<Self::Hasher, DpeErrorCode> {
        let md = Self::get_digest(&profile);
        Ok(SimHasher(
            OpensslHasher::new(md).map_err(|_| DpeErrorCode::InternalError)?,
        ))
    }

    fn derive_cdi(
        profile: DpeProfile,
        measurement_digest: &[u8],
        info: &[u8],
    ) -> Result<Self::Cdi, DpeErrorCode> {
        let base_cdi = vec![0u8; profile.get_cdi_size()];
        let md = Self::get_digest(&profile);

        OpensslCrypto::derive_cdi(base_cdi, measurement_digest, info, md)
            .map_err(|_| DpeErrorCode::InternalError)
    }

    fn derive_ecdsa_pub(
        profile: DpeProfile,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<EcdsaPub, DpeErrorCode> {
        let md = Self::get_digest(&profile);
        let nid = match profile {
            DpeProfile::P256Sha256 => Nid::X9_62_PRIME256V1,
            DpeProfile::P384Sha384 => Nid::SECP384R1,
        };

        let point = OpensslCrypto::derive_ecdsa_pub(cdi, label, info, md, nid)
            .map_err(|_| DpeErrorCode::InternalError)?;

        let mut pub_out = EcdsaPub::default();
        pub_out.x.copy_from_slice(point.x.as_slice());
        pub_out.y.copy_from_slice(point.y.as_slice());
        Ok(pub_out)
    }

    fn ecdsa_sign_with_alias(
        profile: DpeProfile,
        digest: &[u8],
    ) -> Result<EcdsaSignature, DpeErrorCode> {
        let nid = Self::get_curve(&profile);
        let priv_bytes = vec![0u8; profile.get_ecc_int_size()];
        let sig = OpensslCrypto::ecdsa_sign_with_alias(digest, priv_bytes.as_slice(), nid)
            .map_err(|_| DpeErrorCode::InternalError)?;

        let mut sig_out = EcdsaSignature::default();
        sig_out.r.copy_from_slice(sig.r().to_vec().as_slice());
        sig_out.s.copy_from_slice(sig.s().to_vec().as_slice());
        Ok(sig_out)
    }
}
