// Licensed under the Apache-2.0 license

use {
    clap::Parser,
    crypto::OpensslCrypto,
    dpe::commands::{self, CertifyKeyCmd, CommandHdr},
    dpe::context::ContextHandle,
    dpe::dpe_instance::DpeEnv,
    dpe::response::Response,
    dpe::{DpeInstance, Support, DPE_PROFILE},
    pem::{encode_config, EncodeConfig, LineEnding, Pem},
    platform::DefaultPlatform,
    std::fs,
    zerocopy::AsBytes,
};

pub struct TestEnv {
    pub crypto: OpensslCrypto,
    pub platform: DefaultPlatform,
}

impl DpeEnv for TestEnv {
    type Crypto = OpensslCrypto;
    type Platform = DefaultPlatform;

    fn crypto(&mut self) -> &mut OpensslCrypto {
        &mut self.crypto
    }

    fn platform(&mut self) -> &mut DefaultPlatform {
        &mut self.platform
    }
}

/// Tool to generate sample DPE leaf certificate
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File containg DER encoded issuer name
    #[arg(short, long)]
    issuer_name_der_file: Option<String>,
}

fn main() {
    let args = Args::parse();

    let support = Support {
        auto_init: true,
        x509: true,
        ..Support::default()
    };

    let mut env = TestEnv {
        crypto: OpensslCrypto::new(),
        platform: DefaultPlatform,
    };

    let der;
    let mut dpe = match args.issuer_name_der_file {
        Some(file) => {
            der = fs::read(file).unwrap();
            DpeInstance::new(&mut env, support, &der).unwrap()
        }
        None => DpeInstance::new_for_test(&mut env, support).unwrap(),
    };

    let certify_key_cmd: CertifyKeyCmd = commands::CertifyKeyCmd {
        handle: ContextHandle::default(),
        flags: 0,
        label: [0; DPE_PROFILE.get_hash_size()],
        format: commands::CertifyKeyCmd::FORMAT_X509,
    };
    let cmd_body = certify_key_cmd.as_bytes().to_vec();
    let cmd_hdr = CommandHdr::new_for_test(dpe::commands::Command::CertifyKey(certify_key_cmd))
        .as_bytes()
        .to_vec();
    let mut command = cmd_hdr;
    command.extend(cmd_body);

    let resp = dpe
        .execute_serialized_command(&mut env, 0, &command)
        .unwrap();

    let certify_key_response = match resp {
        // Expect CertifyKey response return an error in all other cases.
        Response::CertifyKey(res) => res,
        Response::Error(res) => panic!("Error response {}", res.status),
        _ => panic!("Unexpected Response"),
    };

    let pem = Pem::new(
        "CERTIFICATE",
        &certify_key_response.cert[..certify_key_response.cert_size as usize],
    );

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
