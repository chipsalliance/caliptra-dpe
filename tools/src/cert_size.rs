// Licensed under the Apache-2.0 license

use std::fmt::Display;

use anyhow::{anyhow, Result};
use caliptra_dpe::dpe_instance::DpeEnvImpl;
use caliptra_dpe::{
    commands::{CertifyKeyCommand, CommandExecution, DeriveContextCmd, DeriveContextFlags},
    DpeFlags, DpeProfile, MAX_HANDLES,
};
use caliptra_dpe::{dpe_instance::DpeEnv, response::Response, support::Support, DpeInstance};
use caliptra_dpe_platform::default::{DefaultPlatform, DefaultPlatformProfile};
use clap::{Parser, ValueEnum};

#[cfg(any(feature = "p256", feature = "p384"))]
use self::ec::*;

#[cfg(feature = "p256")]
mod ec {
    pub use caliptra_dpe::commands::CertifyKeyP256Cmd as CertifyKeyCmd;
    pub fn new_crypto() -> caliptra_dpe_crypto::RustCryptoImpl {
        caliptra_dpe_crypto::RustCryptoImpl::new_ecc256()
    }
}
#[cfg(feature = "p384")]
mod ec {
    pub use caliptra_dpe::commands::CertifyKeyP384Cmd as CertifyKeyCmd;
    pub fn new_crypto() -> caliptra_dpe_crypto::RustCryptoImpl {
        caliptra_dpe_crypto::RustCryptoImpl::new_ecc384()
    }
}

#[derive(ValueEnum, Clone, Debug, Copy)]
pub enum Algorithm {
    /// Use EC P256 or P384 depending on the build feature
    Ec,
    /// Use ML-DSA
    Mldsa,
}

impl Default for Algorithm {
    fn default() -> Self {
        if cfg!(any(feature = "p256", feature = "p384")) {
            Algorithm::Ec
        } else {
            Algorithm::Mldsa
        }
    }
}

impl From<Algorithm> for DefaultPlatformProfile {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            #[cfg(feature = "p256")]
            Algorithm::Ec => DefaultPlatformProfile::P256,
            #[cfg(feature = "p384")]
            Algorithm::Ec => DefaultPlatformProfile::P384,
            #[cfg(feature = "ml-dsa")]
            Algorithm::Mldsa => DefaultPlatformProfile::Mldsa87,
            #[allow(unreachable_patterns)]
            _ => panic!("Unsupported algorithm"),
        }
    }
}

impl From<Algorithm> for DpeProfile {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            #[cfg(feature = "p256")]
            Algorithm::Ec => DpeProfile::P256Sha256,
            #[cfg(feature = "p384")]
            Algorithm::Ec => DpeProfile::P384Sha384,
            #[cfg(feature = "ml-dsa")]
            Algorithm::Mldsa => DpeProfile::Mldsa87,
            #[allow(unreachable_patterns)]
            _ => panic!("Unsupported algorithm"),
        }
    }
}

/// Starts a DPE simulator that will receive commands and send responses over unix streams.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Which algorithm to use.
    #[arg(long, short, value_enum, default_value_t = Algorithm::default())]
    algorithm: Algorithm,
    /// Number of contexts to create.
    #[arg(long, short, default_value_t = 1)]
    num_contexts: usize,
    /// Whether to generate a cert or CSR
    #[arg(long)]
    cert: bool,
}

fn send_certify_key(dpe: &mut DpeInstance, env: &mut dyn DpeEnv, args: &Args) -> Result<Response> {
    let format = if args.cert {
        CertifyKeyCommand::FORMAT_X509
    } else {
        CertifyKeyCommand::FORMAT_CSR
    };
    match args.algorithm {
        #[cfg(any(feature = "p256", feature = "p384"))]
        Algorithm::Ec => CertifyKeyCmd {
            format,
            ..Default::default()
        }
        .execute(dpe, env, 0)
        .map_err(|e| anyhow!("DPE error certifying key: {e:?}")),
        #[cfg(feature = "ml-dsa")]
        Algorithm::Mldsa => caliptra_dpe::commands::CertifyKeyMldsa87Cmd {
            format,
            ..Default::default()
        }
        .execute(dpe, env, 0)
        .map_err(|e| anyhow!("DPE error certifying key: {e:?}")),
        #[allow(unreachable_patterns)]
        _ => Err(anyhow!("Unsupported algorithm")),
    }
}

#[derive(Debug)]
pub(crate) enum CertOrCsrSize {
    Cert(usize),
    Csr(usize),
}

impl Display for CertOrCsrSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertOrCsrSize::Cert(size) => {
                write!(f, "certificate size = {}", size)
            }
            CertOrCsrSize::Csr(size) => {
                write!(f, "csr size = {}", size)
            }
        }
    }
}

pub(crate) fn calculate_cert_csr_size(env: &mut dyn DpeEnv, args: &Args) -> Result<CertOrCsrSize> {
    let mut dpe = DpeInstance::new(env, args.algorithm.into())
        .map_err(|e| anyhow!("DPE error creating instance: {e:?}"))?;

    if args.num_contexts > MAX_HANDLES {
        return Err(anyhow!("Too many contexts. Max is {MAX_HANDLES}."));
    }
    let mut flags = DeriveContextFlags::MAKE_DEFAULT
        | DeriveContextFlags::INTERNAL_INPUT_INFO
        | DeriveContextFlags::INTERNAL_INPUT_DICE;
    if args.cert {
        flags |= DeriveContextFlags::INPUT_ALLOW_X509;
    }

    // Minus 1 to account for the default context
    for i in 0..args.num_contexts - 1 {
        let _resp = DeriveContextCmd {
            flags,
            tci_type: i as u32 + 1,
            ..Default::default()
        }
        .execute(&mut dpe, env, 0)
        .map_err(|e| anyhow!("DPE error creating {i}th context: {e:?}"))?;
    }

    let certify_resp = send_certify_key(&mut dpe, env, args)?;
    let Response::CertifyKey(certify_resp) = certify_resp else {
        return Err(anyhow!("Unexpected response type"));
    };
    let len = certify_resp
        .cert()
        .map_err(|_| anyhow!("Error retrieving certificate"))?
        .len();

    if args.cert {
        Ok(CertOrCsrSize::Cert(len))
    } else {
        Ok(CertOrCsrSize::Csr(len))
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut support = Support::default();
    support.set(Support::SIMULATION, true);
    support.set(Support::AUTO_INIT, true);
    support.set(Support::X509, args.cert);
    support.set(Support::CSR, !args.cert);
    support.set(Support::RECURSIVE, true);
    support.set(Support::ROTATE_CONTEXT, true);
    support.set(Support::INTERNAL_DICE, true);
    support.set(Support::INTERNAL_INFO, true);
    support.set(Support::RETAIN_PARENT_CONTEXT, true);
    support.set(Support::CDI_EXPORT, true);

    let flags = DpeFlags::empty();
    let mut state = caliptra_dpe::State::new(support, flags);

    let size: Result<CertOrCsrSize> = match args.algorithm {
        #[cfg(any(feature = "p256", feature = "p384"))]
        Algorithm::Ec => calculate_cert_csr_size(
            &mut DpeEnvImpl {
                crypto: &mut ec::new_crypto(),
                platform: &mut DefaultPlatform(args.algorithm.into()),
                state: &mut state,
            },
            &args,
        ),
        #[cfg(feature = "ml-dsa")]
        Algorithm::Mldsa => calculate_cert_csr_size(
            &mut DpeEnvImpl {
                crypto: &mut caliptra_dpe_crypto::RustCryptoImpl::new_mldsa87(),
                platform: &mut DefaultPlatform(DefaultPlatformProfile::Mldsa87),
                state: &mut state,
            },
            &args,
        ),
        #[allow(unreachable_patterns)]
        _ => Err(anyhow!("Unsupported algorithm")),
    };

    match size {
        Ok(ccs) => {
            println!("{}", ccs);
        }
        Err(e) => {
            eprintln!("{:?}", e);
        }
    }

    Ok(())
}
