// Licensed under the Apache-2.0 license

use alg::*;
use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use dpe::{
    commands::{CertifyKeyCommand, CertifyKeyFlags, CommandExecution, DeriveContextFlags},
    context::ContextHandle,
    DpeFlags, DPE_PROFILE,
};
use dpe::{
    dpe_instance::{DpeEnv, DpeTypes},
    response::Response,
    support::Support,
    DpeInstance,
};
use platform::default::{DefaultPlatform, DefaultPlatformProfile};

#[cfg(feature = "p256")]
mod alg {
    pub use super::Algorithm::Ec as DefaultAlg;
    pub use crypto::Ecdsa256RustCrypto as EcdsaRustCrypto;
    pub use dpe::commands::{
        CertifyKeyP256Cmd as CertifyKeyCmd, DeriveContextP256Cmd as DeriveContextCmd,
    };
}
#[cfg(feature = "p384")]
mod alg {
    pub use super::Algorithm::Ec as DefaultAlg;
    pub use crypto::Ecdsa384RustCrypto as EcdsaRustCrypto;
    pub use dpe::commands::{
        CertifyKeyP384Cmd as CertifyKeyCmd, DeriveContextP384Cmd as DeriveContextCmd,
    };
}
#[cfg(feature = "ml-dsa")]
mod alg {
    pub use super::Algorithm::Mldsa as DefaultAlg;
    pub use crypto::MldsaRustCrypto;
    pub use dpe::commands::{
        CertifyKeyMldsaExternalMu87Cmd as CertifyKeyCmd,
        DeriveContextMldsaExternalMu87Cmd as DeriveContextCmd,
    };
}

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum Algorithm {
    /// Use EC P256 or P384 depending on the build feature
    #[cfg(any(feature = "p256", feature = "p384"))]
    #[default]
    Ec,
    #[cfg(feature = "ml-dsa")]
    #[default]
    /// Use ML-DSA
    Mldsa,
}

impl From<Algorithm> for DefaultPlatformProfile {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            #[cfg(feature = "p256")]
            Algorithm::Ec => DefaultPlatformProfile::P256,
            #[cfg(feature = "p384")]
            Algorithm::Ec => DefaultPlatformProfile::P384,
            #[cfg(feature = "ml-dsa")]
            Algorithm::Mldsa => DefaultPlatformProfile::Mldsa87ExternalMu,
        }
    }
}

/// Starts a DPE simulator that will receive commands and send responses over unix streams.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Which algorithm to use.
    #[arg(long, short, value_enum, default_value_t = DefaultAlg)]
    algorithm: Algorithm,
    /// Number of contexts to create.
    #[arg(long, short, default_value_t = 1)]
    num_contexts: usize,
    /// Whether to generate a cert or CSR
    #[arg(long)]
    cert: bool,
}

#[cfg(any(feature = "p256", feature = "p384"))]
struct SimTypesEc;
#[cfg(any(feature = "p256", feature = "p384"))]
impl DpeTypes for SimTypesEc {
    type Crypto<'a> = EcdsaRustCrypto;
    type Platform<'a> = DefaultPlatform;
}

#[cfg(feature = "ml-dsa")]
struct SimTypesMldsa;
#[cfg(feature = "ml-dsa")]
impl DpeTypes for SimTypesMldsa {
    type Crypto<'a> = MldsaRustCrypto;
    type Platform<'a> = DefaultPlatform;
}

fn run<T: DpeTypes>(env: &mut DpeEnv<T>, args: &Args) -> Result<()> {
    let mut dpe =
        DpeInstance::new(env).map_err(|e| anyhow!("DPE error creating instance: {e:?}"))?;

    // Minus 1 to account for the default context
    for i in 0..args.num_contexts - 1 {
        let _resp = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: [1; DPE_PROFILE.tci_size()],
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::INTERNAL_INPUT_INFO
                | DeriveContextFlags::INTERNAL_INPUT_DICE,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        }
        .execute(&mut dpe, env, 0)
        .map_err(|e| anyhow!("DPE error creating {i}th context: {e:?}"));
    }

    let certify_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        label: [0; DPE_PROFILE.hash_size()],
        format: if args.cert {
            CertifyKeyCommand::FORMAT_X509
        } else {
            CertifyKeyCommand::FORMAT_CSR
        },
    };

    let certify_resp = CertifyKeyCommand::from(&certify_cmd)
        .execute(&mut dpe, env, 0)
        .map_err(|e| anyhow!("DPE error certifying key: {e:?}"))?;
    let Response::CertifyKey(certify_resp) = certify_resp else {
        return Err(anyhow!("Unexpected response type"));
    };
    let len = certify_resp
        .cert()
        .expect("Failed to parse cert from response")
        .len();
    println!(
        "Total {} size: {len}",
        if args.cert { "certificate" } else { "CSR" }
    );
    Ok(())
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
    let mut state = dpe::State::new(support, flags);

    match args.algorithm {
        #[cfg(any(feature = "p256", feature = "p384"))]
        Algorithm::Ec => run(
            &mut DpeEnv::<SimTypesEc> {
                crypto: EcdsaRustCrypto::new(),
                platform: DefaultPlatform(DefaultPlatformProfile::P256),
                state: &mut state,
            },
            &args,
        ),
        #[cfg(feature = "ml-dsa")]
        Algorithm::Mldsa => run(
            &mut DpeEnv::<SimTypesMldsa> {
                crypto: MldsaRustCrypto::new(),
                platform: DefaultPlatform(DefaultPlatformProfile::Mldsa87ExternalMu),
                state: &mut state,
            },
            &args,
        ),
    }
}
