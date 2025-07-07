// Licensed under the Apache-2.0 license

use dpe::DpeFlags;
use platform::default::DefaultPlatformProfile;
use std::env;

use {
    crypto::RustCryptoImpl,
    dpe::commands::{self, CertifyKeyCmd, CertifyKeyFlags, DeriveContextCmd, DeriveContextFlags},
    dpe::context::ContextHandle,
    dpe::dpe_instance::{DpeEnv, DpeTypes},
    dpe::response::Response,
    dpe::{support::Support, DpeInstance, DPE_PROFILE},
    pem::{encode_config, EncodeConfig, LineEnding, Pem},
    platform::default::DefaultPlatform,
    zerocopy::IntoBytes,
};

#[cfg(feature = "dpe_profile_p256_sha256")]
use crypto::Ecdsa256RustCrypto;

#[cfg(feature = "dpe_profile_p384_sha384")]
use crypto::Ecdsa384RustCrypto;

pub struct TestTypes {}

impl DpeTypes for TestTypes {
    #[cfg(feature = "dpe_profile_p256_sha256")]
    type Crypto<'a> = Ecdsa256RustCrypto;

    #[cfg(feature = "dpe_profile_p384_sha384")]
    type Crypto<'a> = Ecdsa384RustCrypto;

    type Platform<'a> = DefaultPlatform;
}

// Call DeriveContext on the default context so the generated cert will have a
// TcbInfo populated.
fn add_tcb_info(
    dpe: &mut DpeInstance,
    env: &mut DpeEnv<TestTypes>,
    data: &[u8; DPE_PROFILE.hash_size()],
    tci_type: u32,
    svn: u32,
) {
    let cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: *data,
        flags: DeriveContextFlags::MAKE_DEFAULT,
        tci_type,
        target_locality: 0, // Unused since flag isn't set
        svn,
    };
    let cmd_body = cmd.as_bytes().to_vec();
    let cmd_hdr = dpe
        .command_hdr(dpe::commands::Command::DERIVE_CONTEXT)
        .as_bytes()
        .to_vec();
    let mut command = cmd_hdr;
    command.extend(cmd_body);

    let resp = dpe.execute_serialized_command(env, 0, &command).unwrap();

    let _ = match resp {
        // Expect CertifyKey response return an error in all other cases.
        Response::DeriveContext(res) => res,
        Response::Error(res) => panic!("Error response {}", res.status),
        _ => panic!("Unexpected Response"),
    };
}

fn certify_key(dpe: &mut DpeInstance, env: &mut DpeEnv<TestTypes>, format: u32) -> Vec<u8> {
    let certify_key_cmd: CertifyKeyCmd = commands::CertifyKeyCmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
        label: [0; DPE_PROFILE.hash_size()],
        format,
    };
    let cmd_body = certify_key_cmd.as_bytes().to_vec();
    let cmd_hdr = dpe
        .command_hdr(dpe::commands::Command::CERTIFY_KEY)
        .as_bytes()
        .to_vec();
    let mut command = cmd_hdr;
    command.extend(cmd_body);

    let resp = dpe.execute_serialized_command(env, 0, &command).unwrap();

    let certify_key_response = match resp {
        // Expect CertifyKey response return an error in all other cases.
        Response::CertifyKey(res) => res,
        Response::Error(res) => panic!("Error response {}", res.status),
        _ => panic!("Unexpected Response"),
    };

    certify_key_response.cert[..certify_key_response.cert_size as usize].to_vec()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (format, format_str) = if args.len() > 1 {
        let arg = &args[1];
        if arg == "csr" {
            (commands::CertifyKeyCmd::FORMAT_CSR, "PKCS7")
        } else if arg == "x509" {
            (commands::CertifyKeyCmd::FORMAT_X509, "CERTIFICATE")
        } else {
            panic!("Unsupported format {}", arg)
        }
    } else {
        (commands::CertifyKeyCmd::FORMAT_X509, "CERTIFICATE")
    };
    let support = Support::AUTO_INIT | Support::X509 | Support::CSR;

    #[cfg(feature = "dpe_profile_p256_sha256")]
    let p = DefaultPlatformProfile::P256;
    #[cfg(feature = "dpe_profile_p384_sha384")]
    let p = DefaultPlatformProfile::P384;
    let mut env = DpeEnv::<TestTypes> {
        crypto: RustCryptoImpl::new(),
        platform: DefaultPlatform(p),
        state: &mut dpe::State::new(support, DpeFlags::empty()),
    };

    let mut dpe = DpeInstance::new(&mut env).unwrap();

    add_tcb_info(
        &mut dpe,
        &mut env,
        &[0; DPE_PROFILE.hash_size()],
        u32::from_be_bytes(*b"TEST"),
        0,
    );
    let cert = certify_key(&mut dpe, &mut env, format);

    let pem = Pem::new(format_str, cert);

    print!(
        "{}",
        encode_config(
            &pem,
            EncodeConfig {
                line_ending: LineEnding::LF
            }
        )
    );
}
