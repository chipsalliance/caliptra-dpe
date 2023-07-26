# Brief setup notes
- Fuzzer requires coredumps, provide these: `sudo sysctl kernel.core_uses_pid=0 && sudo sysctl kernel.core_pattern=core`
- Performance optimisation: `sudo sysctl kernel.sched_child_runs_first=1`

# Building/Testing
- *Cleanup*: `rm -rf fuzz-*.log corpus/fuzz_target_1 artifacts/fuzz_target_1 coverage target`
  - `mkdir -p corpus/fuzz_target_1 artifacts/fuzz_target_1`

**Fuzz**: `~/.local/share/afl.rs/rustc-1.73.0-nightly-da6b55c/afl.rs-0.13.3/afl/bin/afl-whatsup artifacts/fuzz_target_1` useful to retrieve all statuses
Initialise base options:
- Note: `-G` seems stable now; `-L` is apparently acceptable
```
cp ../common_corpus/* corpus/fuzz_target_1/
export CARGO_AFL_BUILD_STANDARD="cargo +nightly afl build" && \
export CARGO_AFL_RUN_A_STANDARD="cargo +nightly afl fuzz -i corpus/fuzz_target_1 -o artifacts/fuzz_target_1 -G 64 -p fast -L 1 -l 2ATR"
```

Workers (TODO: Parallelisation):
- Standard:
```
$CARGO_AFL_BUILD_STANDARD && \
cp target/debug/fuzz_target_1 standard; \
$CARGO_AFL_RUN_A_STANDARD -M node01 ./standard
```
- CmpLog:
```
AFL_LLVM_CMPLOG=1 $CARGO_AFL_BUILD_STANDARD && \
cp target/debug/fuzz_target_1 cmplog; \
$CARGO_AFL_RUN_A_STANDARD -c ./cmplog -S node02 ./standard
```

**Coverage**: Also `afl-plot`?
- `~/.local/share/afl.rs/rustc-1.73.0-nightly-da6b55c/afl.rs-0.13.3/afl/bin/afl-showmap -C -i artifacts/fuzz_target_1/ -o coverage -- ./standard`

## Seed corpus
A seed corpus has been been generated from the defaults and tests in `../common_corpus/`
- TODO: Check impact.

**Open question**: - How could a dictionary help?

# Minimisation
- TODO
