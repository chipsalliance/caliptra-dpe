// Licensed under the Apache-2.0 license

#![cfg_attr(feature = "libfuzzer-sys", no_main)]

#[cfg(all(not(feature = "libfuzzer-sys"), not(feature = "afl")))]
compile_error!("Either feature \"libfuzzer-sys\" or \"afl\" must be enabled!");

#[cfg(feature = "libfuzzer-sys")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "afl")]
use afl::fuzz;

use log::{trace, LevelFilter};
use simplelog::{Config, WriteLogger};
use std::fs::OpenOptions;

use crypto::OpensslCrypto;
use dpe::dpe_instance::DpeEnv;
use dpe::{commands::Command, response::Response, DpeInstance, Support};
use platform::{DefaultPlatform, AUTO_INIT_LOCALITY};

// https://github.com/chipsalliance/caliptra-sw/issues/624 will consider matrix fuzzing.
const SUPPORT: Support = Support {
    simulation: true,
    extend_tci: true,
    auto_init: true,
    tagging: true,
    rotate_context: true,
    x509: true,
    csr: true,
    is_ca: true,
    is_symmetric: true,
    internal_info: true,
    internal_dice: true,
};

struct SimEnv {
    platform: DefaultPlatform,
    crypto: OpensslCrypto,
}

impl DpeEnv for SimEnv {
    type Crypto = OpensslCrypto;
    type Platform = DefaultPlatform;

    fn crypto(&mut self) -> &mut OpensslCrypto {
        &mut self.crypto
    }

    fn platform(&mut self) -> &mut DefaultPlatform {
        &mut self.platform
    }
}

// Although fuzzers use persistent mode, using an internal worker shortens the lifetime.
// So, no risk of double-initialising or destroying the context.
fn harness(data: &[u8]) {
    // NOTE: This is racey
    let _ = WriteLogger::init(
        LevelFilter::Off,
        //LevelFilter::Trace,
        Config::default(),
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("dpe_fuzz.log")
            .unwrap(),
    );

    trace!("----------------------------------");
    if let Ok(command) = Command::deserialize(data) {
        trace!("| Fuzzer's locality requested {command:x?}",);
        trace!("|");
    } else {
        trace!("| Fuzzer's locality requested invalid command. {data:02x?}");
        trace!("----------------------------------");
        return;
    }

    // `new_for_test()` simply defines the issuer
    let mut env = SimEnv {
        crypto: OpensslCrypto::new(),
        platform: DefaultPlatform,
    };
    let mut dpe = DpeInstance::new_for_test(&mut env, SUPPORT).unwrap();

    // Hard-code working locality
    let response = dpe
        .execute_serialized_command(&mut env, AUTO_INIT_LOCALITY, data)
        .unwrap();

    let response_code = match response {
        Response::GetProfile(ref res) => res.resp_hdr.status,
        Response::InitCtx(ref res) => res.resp_hdr.status,
        Response::DeriveChild(ref res) => res.resp_hdr.status,
        Response::RotateCtx(ref res) => res.resp_hdr.status,
        Response::CertifyKey(ref res) => res.resp_hdr.status,
        Response::Sign(ref res) => res.resp_hdr.status,
        Response::DestroyCtx(ref resp_hdr) => resp_hdr.status,
        Response::ExtendTci(ref res) => res.resp_hdr.status,
        Response::TagTci(ref res) => res.resp_hdr.status,
        Response::GetTaggedTci(ref res) => res.resp_hdr.status,
        Response::GetCertificateChain(ref res) => res.resp_hdr.status,
        Response::Error(ref resp_hdr) => resp_hdr.status,
    };
    // There are a few vendor error codes starting at 0x1000, so this can be a 2 bytes.
    trace!("| Response Code {response_code:#06x}");
    trace!("----------------------------------");
}

// cargo-fuzz target
#[cfg(feature = "libfuzzer-sys")]
fuzz_target!(|data: &[u8]| {
    harness(data);
});

// cargo-afl target
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data: &[u8]| {
        harness(data);
    });
}
