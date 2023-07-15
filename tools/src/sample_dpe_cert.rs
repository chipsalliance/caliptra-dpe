use {
    dpe::{DpeInstance, DPE_PROFILE, Support},
    dpe::commands::{self, CertifyKeyCmd, CommandHdr, InitCtxCmd, CommandExecution},
    dpe::response::Response,
    dpe::context::ContextHandle,
    pem::{Pem, encode_config, EncodeConfig, LineEnding},
    platform::DefaultPlatform,
    crypto::OpensslCrypto,
    zerocopy::AsBytes,
    platform::AUTO_INIT_LOCALITY,
};

fn main() {
    let mut crypto = OpensslCrypto::new();

    let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(
        Support {
            x509: true,
            ..Support::default()
        },         
        &mut crypto,
    ).unwrap();

    const TEST_LOCALITIES: [u32; 2] = [AUTO_INIT_LOCALITY, u32::from_be_bytes(*b"OTHR")];
    const SIMULATION_HANDLE: ContextHandle =
    ContextHandle([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    let init_resp = match InitCtxCmd::new_use_default()
    .execute(&mut dpe, TEST_LOCALITIES[0], &mut crypto)
    .unwrap()
    {
        Response::InitCtx(resp) => resp,
        _ => panic!("Incorrect return type."),
    };

    let CERTIFY_KEY_CMD: CertifyKeyCmd = commands::CertifyKeyCmd{
        handle: init_resp.handle,
        flags: 0,
        label: [0; DPE_PROFILE.get_hash_size()],
        format: commands::CertifyKeyCmd::FORMAT_X509,
    };
    let cmd_hdr = CommandHdr::new_for_test(dpe::commands::Command::CertifyKey(CERTIFY_KEY_CMD));

    let CERTIFY_KEY_CMD2: CertifyKeyCmd = commands::CertifyKeyCmd{
        handle: init_resp.handle,
        flags: 0,
        label: [0; DPE_PROFILE.get_hash_size()],
        format: commands::CertifyKeyCmd::FORMAT_X509,
    };
    let mut command = cmd_hdr
        .as_bytes()
        .to_vec();
    command.extend(CERTIFY_KEY_CMD2.as_bytes());

    let resp = dpe.execute_serialized_command(0, &command, &mut crypto).unwrap();

    let certify_key_response = match resp {
        // Expect CertifyKey response return an error in all other cases.
        Response::CertifyKey(res) => res,
        Response::Error(res) =>  panic!("Error response {}", res.status),
        _ => panic!("Unexpected Response"),
    };

    let pem = Pem::new(
        "CERTIFICATE",
        &certify_key_response.cert[..usize::try_from(certify_key_response.cert_size).unwrap()]);

    println!("{}", encode_config(&pem, EncodeConfig { line_ending: LineEnding::LF }));
}
