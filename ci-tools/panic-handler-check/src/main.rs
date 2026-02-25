// Licensed under the Apache-2.0 license

pub use crypto::Ecdsa256RustCrypto as RustCrypto;
use dpe::DpeFlags;
use dpe::DpeInstance;
use dpe::dpe_instance::{DpeEnv, DpeTypes};
use dpe::support::Support;
use platform::dummy::{DefaultPlatform, DefaultPlatformProfile};

struct SimTypes {}

impl DpeTypes for SimTypes {
    type Crypto<'a> = RustCrypto;

    type Platform<'a> = DefaultPlatform;
}

fn main() {
    let mut flags = DpeFlags::empty();
    flags.set(DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL, true);

    let mut env = DpeEnv::<SimTypes> {
        crypto: <SimTypes as DpeTypes>::Crypto::new(),
        platform: DefaultPlatform(DefaultPlatformProfile::P256),
        state: &mut dpe::State::new(Support::default(), flags),
    };
    let mut dpe = DpeInstance::new(&mut env, dpe::DpeProfile::P256Sha256).unwrap();
    test_execute_serialized_command(&mut dpe, &mut env);
    test_roll_onetime_use_handle(&mut dpe, &mut env);
    test_get_profile(&mut dpe, &mut env);
    test_deserialize_command(&mut dpe);

    println!(
        "{:?}",
        sanity_check(
            std::env::args().next().unwrap().parse().unwrap(),
            std::env::args().next().unwrap().parse().unwrap()
        )
    );
}

#[no_panic::no_panic]
fn test_execute_serialized_command(dpe: &mut DpeInstance, env: &mut DpeEnv<SimTypes>) {
    let _ = dpe.execute_serialized_command(env, 1, &[0]);
}

#[no_panic::no_panic]
fn test_roll_onetime_use_handle(dpe: &mut DpeInstance, env: &mut DpeEnv<SimTypes>) {
    let _ = dpe.roll_onetime_use_handle(env, 1);
}

#[no_panic::no_panic]
fn test_get_profile(dpe: &mut DpeInstance, env: &mut DpeEnv<SimTypes>) {
    let _ = dpe.get_profile(&mut env.platform, env.state.support);
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
fn sanity_check(a: u8, b: u8) -> Result<(), ()> {
    if a > b {
        return Ok(());
    } else {
        return Err(());
    }
}
