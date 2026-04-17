// Licensed under the Apache-2.0 license

#[cfg(not(any(feature = "p256", feature = "p384", feature = "ml-dsa")))]
compile_error!("select one of the features p256, p384, ml-dsa");

use std::hint::black_box;

use crypto::dummy::DummyCrypto;
use dpe::dpe_instance::{DpeEnv, DpeEnvImpl};
use dpe::support::Support;
use dpe::DpeFlags;
use dpe::DpeInstance;
use dpe::DpeProfile;
use platform::dummy::{DefaultPlatform, DefaultPlatformProfile};

fn main() {
    let mut flags = DpeFlags::empty();
    flags.set(DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL, true);

    #[cfg(feature = "p256")]
    let platform_profile = DefaultPlatformProfile::P256;
    #[cfg(feature = "p256")]
    let dpe_profile = DpeProfile::P256Sha256;
    #[cfg(feature = "p384")]
    let platform_profile = DefaultPlatformProfile::P384;
    #[cfg(feature = "p384")]
    let dpe_profile = DpeProfile::P384Sha384;
    #[cfg(feature = "ml-dsa")]
    let platform_profile = DefaultPlatformProfile::Mldsa87;
    #[cfg(feature = "ml-dsa")]
    let dpe_profile = DpeProfile::Mldsa87;

    let mut crypto = DummyCrypto::new();
    let mut platform = DefaultPlatform(platform_profile);
    let mut state = dpe::State::new(Support::default(), flags);
    let mut env = DpeEnvImpl {
        crypto: &mut crypto,
        platform: &mut platform,
        state: &mut state,
    };
    let mut dpe = DpeInstance::new(&mut env, dpe_profile).unwrap();
    test_execute_serialized_command(&mut dpe, &mut env);
    test_roll_onetime_use_handle(&mut dpe, &mut env);
    test_get_profile(&mut dpe, &mut env);
    test_deserialize_command(&mut dpe);

    let _ = black_box(rerun_with_release_profile(8));
}

#[no_panic::no_panic]
fn test_execute_serialized_command(dpe: &mut DpeInstance, env: &mut dyn DpeEnv) {
    let _ = dpe.execute_serialized_command(env, 1, &[0]);
}

#[no_panic::no_panic]
fn test_roll_onetime_use_handle(dpe: &mut DpeInstance, env: &mut dyn DpeEnv) {
    let _ = dpe.roll_onetime_use_handle(env, 1);
}

#[no_panic::no_panic]
fn test_get_profile(dpe: &mut DpeInstance, env: &mut dyn DpeEnv) {
    let support = env.state().support;
    let _ = dpe.get_profile(env.platform(), support);
}

#[no_panic::no_panic]
fn test_deserialize_command(dpe: &mut DpeInstance) {
    let _ = dpe.deserialize_command(&[0]);
}

/// Sanitiy check to verify that `no_panic` correctly detects the absence of panics in this function
///
/// If this fails you might have to compile with more optimizations.
/// (Build with `--release` profile.)
#[no_panic::no_panic]
fn rerun_with_release_profile(a: usize) -> Result<u8, ()> {
    let buf = [0; 5];
    if a >= buf.len() {
        return Err(());
    } else {
        return Ok(buf[a]);
    }
}
