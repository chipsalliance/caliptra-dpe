// Licensed under the Apache-2.0 license

use {
    crypto::OpensslCrypto,
    dpe::commands::{self, CertifyKeyCmd, CertifyKeyFlags, CommandHdr},
    dpe::context::ContextHandle,
    dpe::dpe_instance::{DpeEnv, DpeTypes},
    dpe::response::Response,
    dpe::{support::Support, DpeInstance, DPE_PROFILE},
    pem::{encode_config, EncodeConfig, LineEnding, Pem},
    platform::DefaultPlatform,
    zerocopy::AsBytes,
};

pub struct TestTypes {}

impl DpeTypes for TestTypes {
    type Crypto<'a> = OpensslCrypto;
    type Platform<'a> = DefaultPlatform;
}

fn main() {
    let support = Support::AUTO_INIT | Support::X509;

    let mut env = DpeEnv::<TestTypes> {
        crypto: OpensslCrypto::new(),
        platform: DefaultPlatform,
    };

    let mut dpe = DpeInstance::new(&mut env, support).unwrap();

    let certify_key_cmd: CertifyKeyCmd = commands::CertifyKeyCmd {
        handle: ContextHandle::default(),
        flags: CertifyKeyFlags::empty(),
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
