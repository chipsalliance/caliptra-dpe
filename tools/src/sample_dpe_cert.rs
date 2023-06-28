use {
    dpe::{DpeInstance, DPE_PROFILE, Support},
    dpe::commands::{self, CertifyKeyCmd, CommandHdr},
    dpe::response::Response,
    dpe::context::ContextHandle,
    pem::{Pem, encode_config, EncodeConfig, LineEnding},
    platform::DefaultPlatform,
    crypto::OpensslCrypto,
    zerocopy::AsBytes,
};

fn main() {
    let mut dpe = DpeInstance::<OpensslCrypto, DefaultPlatform>::new_for_test(Support {
        auto_init: true,
        ..Support::default()
    })
    .unwrap();

    const CERTIFY_KEY_CMD: CertifyKeyCmd = commands::CertifyKeyCmd{
        handle: ContextHandle::default(),
        flags: 0,
        label: [0; DPE_PROFILE.get_hash_size()],
        format: commands::CertifyKeyCmd::FORMAT_X509,
    };
    let cmd_hdr = CommandHdr::new_for_test(dpe::commands::Command::CertifyKey(CERTIFY_KEY_CMD));

    let mut command = cmd_hdr
        .as_bytes()
        .to_vec();
    command.extend(CERTIFY_KEY_CMD.as_bytes());

    let resp = dpe.execute_serialized_command(0, &command).unwrap();

    let certify_key_response = match resp {
        // Expect CertifyKey response return an error in all other cases.
        Response::CertifyKey(res) => res,
        _ => panic!("Unexpected Response"),
    };

    let pem = Pem::new(
        "CERTIFICATE",
        &certify_key_response.cert[..usize::try_from(certify_key_response.cert_size).unwrap()]);

    println!("{}", encode_config(&pem, EncodeConfig { line_ending: LineEnding::LF }));
}
