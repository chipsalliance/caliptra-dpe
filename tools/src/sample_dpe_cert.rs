use {
    crypto::OpensslCrypto,
    dpe::commands::{self, CertifyKeyCmd, CommandExecution, CommandHdr, InitCtxCmd},
    dpe::context::ContextHandle,
    dpe::dpe_instance::DpeEnv,
    dpe::response::Response,
    dpe::{DpeInstance, Support, DPE_PROFILE},
    pem::{encode_config, EncodeConfig, LineEnding, Pem},
    platform::DefaultPlatform,
    platform::AUTO_INIT_LOCALITY,
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
            x509: true,
            ..Support::default()
        },
    )
    .unwrap();

    const TEST_LOCALITIES: [u32; 2] = [AUTO_INIT_LOCALITY, u32::from_be_bytes(*b"OTHR")];
    const SIMULATION_HANDLE: ContextHandle =
        ContextHandle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    let init_resp = match InitCtxCmd::new_use_default()
        .execute(&mut dpe, &mut env, TEST_LOCALITIES[0])
        .unwrap()
    {
        Response::InitCtx(resp) => resp,
        _ => panic!("Incorrect return type."),
    };

    let CERTIFY_KEY_CMD: CertifyKeyCmd = commands::CertifyKeyCmd {
        handle: init_resp.handle,
        flags: 0,
        label: [0; DPE_PROFILE.get_hash_size()],
        format: commands::CertifyKeyCmd::FORMAT_X509,
    };
    let cmd_hdr = CommandHdr::new_for_test(dpe::commands::Command::CertifyKey(CERTIFY_KEY_CMD));

    let CERTIFY_KEY_CMD2: CertifyKeyCmd = commands::CertifyKeyCmd {
        handle: init_resp.handle,
        flags: 0,
        label: [0; DPE_PROFILE.get_hash_size()],
        format: commands::CertifyKeyCmd::FORMAT_X509,
    };
    let mut command = cmd_hdr.as_bytes().to_vec();
    command.extend(CERTIFY_KEY_CMD2.as_bytes());

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
        &certify_key_response.cert[..usize::try_from(certify_key_response.cert_size).unwrap()],
    );

    println!(
        "{}",
        encode_config(
            &pem,
            EncodeConfig {
                line_ending: LineEnding::LF
            }
        )
    );
}
