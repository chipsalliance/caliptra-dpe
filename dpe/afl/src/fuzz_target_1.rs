// Licensed under the Apache-2.0 license

use afl::fuzz;

mod runtime_dpe_dpe_fuzz_harness;
use runtime_dpe_dpe_fuzz_harness::harness;

fn main() {
    fuzz!(|data: &[u8]| {
        harness(data);
    });
}
