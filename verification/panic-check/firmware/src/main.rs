// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

#[cfg(not(any(feature = "p256", feature = "p384", feature = "ml-dsa")))]
compile_error!("select one of the features p256, p384, ml-dsa");

use core::hint::black_box;

use crypto::dummy::DummyCrypto;
use dpe::dpe_instance::DpeEnvImpl;
use dpe::support::Support;
use dpe::DpeFlags;
use dpe::DpeInstance;
use dpe::DpeProfile;
use platform::dummy::{DefaultPlatform, DefaultPlatformProfile};

#[panic_handler]
#[inline(never)]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    panic_is_possible();
    loop {}
}

#[unsafe(no_mangle)]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    main();
    loop {}
}

fn main() {
    // Intentionally panic-able code to verify the checker works.
    // This should cause the panic check to FAIL.
    #[cfg(feature = "should-fail")]
    {
        let arr = [1, 2, 3];
        // Use black_box to prevent compile-time optimization
        let idx = black_box(10);
        // Array bounds check will include panic code in the binary
        let _ = arr[idx];
    }

    let mut flags = DpeFlags::empty();
    flags.set(DpeFlags::MARK_DICE_EXTENSIONS_CRITICAL, true);

    // ml-dsa takes precedence when hybrid (p384 + ml-dsa) is enabled
    #[cfg(all(feature = "p256", not(any(feature = "p384", feature = "ml-dsa"))))]
    let platform_profile = DefaultPlatformProfile::P256;
    #[cfg(all(feature = "p256", not(any(feature = "p384", feature = "ml-dsa"))))]
    let dpe_profile = DpeProfile::P256Sha256;
    #[cfg(all(feature = "p384", not(feature = "ml-dsa")))]
    let platform_profile = DefaultPlatformProfile::P384;
    #[cfg(all(feature = "p384", not(feature = "ml-dsa")))]
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

    let mut dpe = match DpeInstance::new(&mut env, dpe_profile) {
        Ok(dpe) => dpe,
        Err(_) => return,
    };

    let _ = black_box(dpe.execute_serialized_command(&mut env, 1, black_box(&[0])));
}
