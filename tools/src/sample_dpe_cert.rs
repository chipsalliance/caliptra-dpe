// Licensed under the Apache-2.0 license

use {
    crypto::OpensslCrypto,
    dpe::commands::{self, CertifyKeyCmd, CommandHdr},
    dpe::context::ContextHandle,
    dpe::dpe_instance::DpeEnv,
    dpe::response::Response,
    dpe::{DpeInstance, Support, DPE_PROFILE},
    pem::{encode_config, EncodeConfig, LineEnding, Pem},
    platform::DefaultPlatform,
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

fn main() {
    let mut env = TestEnv {
        crypto: OpensslCrypto::new(),
        platform: DefaultPlatform,
    };

    let mut dpe = DpeInstance::new_for_test(
        &mut env,
        Support {
            auto_init: true,
            x509: true,
            ..Support::default()
        },
    )
    .unwrap();

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
