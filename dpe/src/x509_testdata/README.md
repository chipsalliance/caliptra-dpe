# Golden X.509 / CSR regression test data

This directory holds fixed, known-good ("golden") DER artifacts used by the regression smoke tests in `dpe/src/x509.rs` (module `x509::tests::golden`).

Profiles: `p256`, `p384`, `mldsa87`.

The tests treat these files as immutable inputs. They only **parse** and **validate** them:

- parse as a valid X.509v3 certificate / [PKCS#10](https://datatracker.ietf.org/doc/html/rfc2986) CSR
- verify the (self-)signature against the public key embedded in the artifact
- assert on structure and the DICE / TCI extensions (UEID, MultiTcbInfo)

The tests never write to disk and never regenerate these files.

## Regenerating the goldens

The goldens are regenerated with `regen.sh`, which uses **only** the OpenSSL CLI and does not depend on the caliptra-dpe code base.
This independence is deliberate: the regression tests compare DPE's own encoder output against artifacts produced by an external tool, so a change (or a break) in DPE's encoder is caught instead of both sides drifting together silently.

```sh
./regen.sh              # regenerate all profiles (p256, p384, mldsa87)
./regen.sh p256         # regenerate a single profile
```

Requirements: OpenSSL >= 3.5 with the built-in `default` provider (needed for ML-DSA-87). The script:

The authoritative encoding these artifacts mirror lives in `dpe/src/x509.rs` and the golden assertions are in module `x509::tests::golden`.

## Update Golden Certificate

```sh
cargo test -p caliptra-dpe --no-default-features --features p256 golden
cargo test -p caliptra-dpe --no-default-features --features p384 golden
cargo test -p caliptra-dpe --no-default-features --features ml-dsa golden
```

This is a deliberate, reviewed action, not something the test suite performs.

## Inspecting an artifact

Use the OpenSSL CLI to view a golden in human-readable form:

```sh
openssl x509 -in golden_cert_<profile>.der -inform DER -text -noout
openssl req  -in golden_csr_<profile>.der  -inform DER -text -noout
```

ML-DSA-87 inspection requires OpenSSL >= 3.5 with the built-in `default` provider.
