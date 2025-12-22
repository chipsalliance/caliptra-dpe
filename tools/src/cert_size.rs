// Licensed under the Apache-2.0 license

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use dpe::{
    commands::{CertifyKeyCommand, CommandExecution, DeriveContextCmd, DeriveContextFlags},
    DpeFlags, DpeProfile, MAX_HANDLES,
};
use dpe::{
    dpe_instance::{DpeEnv, DpeTypes},
    response::Response,
    support::Support,
    DpeInstance,
};
use platform::default::{DefaultPlatform, DefaultPlatformProfile};

#[cfg(any(feature = "p256", feature = "p384"))]
use self::ec::*;
#[cfg(feature = "ml-dsa")]
use self::ml_dsa::*;

#[cfg(feature = "p256")]
mod ec {
    pub use crypto::Ecdsa256RustCrypto as EcdsaRustCrypto;
    pub use dpe::commands::CertifyKeyP256Cmd as CertifyKeyCmd;
}
#[cfg(feature = "p384")]
mod ec {
    pub use crypto::Ecdsa384RustCrypto as EcdsaRustCrypto;
    pub use dpe::commands::CertifyKeyP384Cmd as CertifyKeyCmd;
}
#[cfg(feature = "ml-dsa")]
mod ml_dsa {
    pub use crypto::MldsaRustCrypto;
    pub use dpe::commands::CertifyKeyMldsa87Cmd as CertifyKeyMldsaCmd;

    pub struct SimTypesMldsa;
    impl dpe::dpe_instance::DpeTypes for SimTypesMldsa {
        type Crypto<'a> = MldsaRustCrypto;
        type Platform<'a> = platform::default::DefaultPlatform;
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

#[cfg(any(feature = "p256", feature = "p384"))]
struct SimTypesEc;
#[cfg(any(feature = "p256", feature = "p384"))]
impl DpeTypes for SimTypesEc {
    type Crypto<'a> = EcdsaRustCrypto;
    type Platform<'a> = DefaultPlatform;
}

fn send_certify_key(
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<impl DpeTypes>,
    args: &Args,
) -> Result<Response> {
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
        Algorithm::Mldsa => CertifyKeyMldsaCmd {
            format,
            ..Default::default()
        }
        .execute(dpe, env, 0)
        .map_err(|e| anyhow!("DPE error certifying key: {e:?}")),
        #[allow(unreachable_patterns)]
        _ => Err(anyhow!("Unsupported algorithm")),
    }
}

fn run<T: DpeTypes>(env: &mut DpeEnv<T>, args: &Args) -> Result<()> {
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
                platform: DefaultPlatform(args.algorithm.into()),
                state: &mut state,
            },
            &args,
        ),
        #[cfg(feature = "ml-dsa")]
        Algorithm::Mldsa => run(
            &mut DpeEnv::<SimTypesMldsa> {
                crypto: MldsaRustCrypto::new(),
                platform: DefaultPlatform(DefaultPlatformProfile::Mldsa87),
                state: &mut state,
            },
            &args,
        ),
        #[allow(unreachable_patterns)]
        _ => Err(anyhow!("Unsupported algorithm")),
    }
}
