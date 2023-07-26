# Brief setup notes
- Fuzzer attempts ptrace attach, permit this: `sudo sysctl kernel.yama.ptrace_scope=0`

# Building/Testing
- *Cleanup*: `rm -rf fuzz-*.log corpus/fuzz_target_1 artifacts/fuzz_target_1 coverage target`
  - `mkdir -p corpus/fuzz_target_1 artifacts/fuzz_target_1`
**Fuzz**: `cargo +nightly fuzz run -s address,leak,memory fuzz_target_1 corpus/fuzz_target_1 ../common_corpus/ -- -max_len=64 -jobs=8` -- **NOTE WELL**: Only one sanitiser can be used at a time.
- TODO: Finalise `max_len`
**Coverage**: `cargo +nightly fuzz coverage -s address,leak,memory fuzz_target_1 corpus/fuzz_target_1 ../common_corpus/ -- -max_len=64` -- **NOTE WELL**: Only one sanitiser can be used at a time.
- Visualisation: `~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_target_1 --format=html -instr-profile=coverage/fuzz_target_1/coverage.profdata > index.html`

## Seed corpus (optional)
Optionally, a seed corpus has been been generated from the defaults and tests in `../common_corpus/`
- TODO: Check impact.

**Open question**: - How could a dictionary help?

# Minimisation
- `mkdir -p corpus_new/fuzz_target_1`
- `cargo +nightly fuzz run -s address,leak,memory fuzz_target_1 corpus_new/fuzz_target_1 corpus/fuzz_target_1 -- -merge=1`
- `rm -rf corpus && mv corpus_new corpus`


# Initial notes
"verification" tests call-order:
- `TestGetProfile()`
- `TestInitializeContext()`
- `TestCertifyKey()`
- `TestTagTCI()`
