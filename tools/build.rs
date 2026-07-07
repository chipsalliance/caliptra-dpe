// Licensed under the Apache-2.0 license

use caliptra_dpe::{
    commands::{
        self, CertifyKeyFlags, CertifyKeyP384Cmd as CertifyKeyCmd, DeriveContextCmd,
        DeriveContextFlags,
    },
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeEnvImpl},
    response::Response,
    support::Support,
    tci::TciMeasurement,
    DpeFlags, DpeInstance, DpeProfile,
};
use caliptra_dpe_platform::default::{DefaultPlatform, DefaultPlatformProfile};
use pem::{encode_config, EncodeConfig, LineEnding, Pem};
use std::{env, fs, path::PathBuf};
use zerocopy::IntoBytes;

fn derive_context(
    dpe: &mut DpeInstance,
    env: &mut dyn DpeEnv,
    handle: ContextHandle,
    data: &TciMeasurement,
    tci_type: u32,
    svn: u32,
    flags: DeriveContextFlags,
) -> (ContextHandle, ContextHandle) {
    let cmd = DeriveContextCmd {
        handle,
        data: *data,
        flags: flags | DeriveContextFlags::INPUT_ALLOW_X509,
        tci_type,
        target_locality: 0,
        svn,
    };
    let cmd_body = cmd.as_bytes().to_vec();
    let cmd_hdr = dpe
        .command_hdr(caliptra_dpe::commands::Command::DERIVE_CONTEXT)
        .as_bytes()
        .to_vec();
    let mut command = cmd_hdr;
    command.extend(cmd_body);

    let resp = dpe.execute_serialized_command(env, 0, &command).unwrap();

    match resp {
        Response::DeriveContext(res) => (res.parent_handle, res.handle),
        Response::Error(res) => panic!(
            "DeriveContext Error response {} for handle {:?}",
            res.status, handle
        ),
        _ => panic!("Unexpected Response"),
    }
}

fn certify_key(dpe: &mut DpeInstance, env: &mut dyn DpeEnv, handle: ContextHandle) -> Vec<u8> {
    let certify_key_cmd = CertifyKeyCmd {
        handle,
        flags: CertifyKeyFlags::empty(),
        label: [0; DpeProfile::P384Sha384.hash_size()],
        format: commands::CertifyKeyCommand::FORMAT_X509,
    };
    let cmd_body = certify_key_cmd.as_bytes().to_vec();
    let cmd_hdr = dpe
        .command_hdr(caliptra_dpe::commands::Command::CERTIFY_KEY)
        .as_bytes()
        .to_vec();
    let mut command = cmd_hdr;
    command.extend(cmd_body);

    let resp = dpe.execute_serialized_command(env, 0, &command).unwrap();

    let certify_key_response = match resp {
        Response::CertifyKey(res) => res,
        Response::Error(res) => panic!("CertifyKey Error response {}", res.status),
        _ => panic!("Unexpected Response"),
    };

    certify_key_response.cert().unwrap().to_vec()
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let support =
        Support::AUTO_INIT | Support::X509 | Support::RETAIN_PARENT_CONTEXT | Support::RECURSIVE;
    let flags = DpeFlags::empty();

    let mut crypto = caliptra_dpe_crypto::RustCryptoImpl::new_ecc384();
    let mut platform = DefaultPlatform(DefaultPlatformProfile::P384);
    let mut state = caliptra_dpe::State::new(support, flags);

    let mut env = DpeEnvImpl {
        crypto: &mut crypto,
        platform: &mut platform,
        state: &mut state,
    };

    let mut dpe = DpeInstance::new(&mut env, DpeProfile::P384Sha384).unwrap();

    // 1. Derive Non-default Parent (Layer 1) from Root (Default context)
    // Retaining parent is not used here so Root is retired and locality becomes non-default.
    let (_root_handle, parent_handle) = derive_context(
        &mut dpe,
        &mut env,
        ContextHandle::default(),
        &TciMeasurement::default(),
        u32::from_be_bytes(*b"FW01"),
        1,
        DeriveContextFlags::empty(),
    );

    // 2. Derive Branch A (Layer 2) from Parent (retaining Parent)
    let (parent_handle_after_a, _branch_a_handle) = derive_context(
        &mut dpe,
        &mut env,
        parent_handle,
        &TciMeasurement::default(),
        u32::from_be_bytes(*b"B_A1"),
        2,
        DeriveContextFlags::RETAIN_PARENT_CONTEXT,
    );

    // 3. Derive Branch B (Layer 2) from Parent (using retained parent_handle_after_a)
    let (parent_handle_after_b, branch_b_handle) = derive_context(
        &mut dpe,
        &mut env,
        parent_handle_after_a,
        &TciMeasurement::default(),
        u32::from_be_bytes(*b"B_B1"),
        2,
        DeriveContextFlags::RETAIN_PARENT_CONTEXT,
    );

    // 4. Derive Sub-branch B1 (Layer 3) from Branch B
    let (_branch_b_after, leaf_handle) = derive_context(
        &mut dpe,
        &mut env,
        branch_b_handle,
        &TciMeasurement::default(),
        u32::from_be_bytes(*b"LEAF"),
        3,
        DeriveContextFlags::empty(),
    );

    let _ = parent_handle_after_b;

    // 5. Certify Key on Leaf
    let cert_bytes = certify_key(&mut dpe, &mut env, leaf_handle);

    let pem_struct = Pem::new("CERTIFICATE", cert_bytes);
    let pem_string = encode_config(
        &pem_struct,
        EncodeConfig {
            line_ending: LineEnding::LF,
        },
    );

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(out_dir).join("sample_cert.pem");
    fs::write(&dest_path, pem_string).unwrap();
}
