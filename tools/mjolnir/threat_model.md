<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Caliptra DPE Security Threat Model

This document outlines the security architecture, trust boundaries, assets, and threat vectors for **Caliptra DPE (Dice Protection Environment)**. It serves as the authoritative threat model context for automated and manual security audits.

---

## 1. System Overview & Trust Boundaries

Caliptra DPE provides cryptographic measurement, context derivation, and X.509 certificate generation services adhering to the DICE Protection Environment architecture.

### Trust Domains:
1. **Core DPE Engine (`dpe/`) [Highest Trust]**:
   * Context handle lifecycle and derivation state machine.
   * Measurement aggregation and certificate chain signing.
   * Access control enforcement across client localities.
   * Privilege isolation enforcement: Privilege Level 1 (PL1) callers are strictly prohibited from mutating or impacting Privilege Level 0 (PL0) state.
2. **Platform & Crypto Layer (`platform/`, `crypto/`) [High Trust]**:
   * Cryptographic primitives (ECDSA P-256, P-384, ML-DSA, SHA-256, SHA-384).
   * Hardware key vault abstraction, CDI derivation, and persistent state storage.
   * Random number generation and nonces.
3. **Response Buffer & Serialization (`response-buffer/`, `dice-asn1/`) [High Trust]**:
   * Fixed-size memory buffers for command serialization and deserialization.
   * ASN.1 DER encoding for X.509 certificates and CSRs.
4. **Transport & Simulator Layer (`simulator/`, `tools/`) [Semi-Trusted / Untrusted Entrypoint]**:
   * Command transport parsing across socket, memory-mapped, and mailbox interfaces.
   * Host emulator bindings and verification test harnesses.
5. **Verification & ABI Client (`verification/`) [Test & Validation Boundary]**:
   * Go client libraries and compliance test suites.

---

## 2. High-Value Assets (HVAs)

* **Compound Device Identifiers (CDIs)**: Layered secrets derived from measurements and root keys.
* **Exported-CDI Handles**: Handles used for delegating or exporting CDI-derived credentials; must be protected against unauthorized access and invalidated upon context teardown.
* **Asymmetric Private Keys**: Device and context signing keys (ECDSA / ML-DSA).
* **Context Handles**: 16-byte cryptographically random or default handles identifying client execution contexts.
* **Measurement Digests**: PCR-equivalent measurements recorded for software identity verification.
* **X.509 Certificate Chains**: Authenticated DICE certificate trees anchored to the Caliptra RoT.

---

## 3. Key Threat Categories

### 3.1. Context Isolation & Handle Manipulation (Privilege Escalation / Spoofing)
* **Threat**: Malicious client attempting to access, rotate, certify, or destroy a DPE context belonging to a different locality or client.
* **Security Requirements**:
  * Strict locality validation on all commands (`InitCtx`, `DeriveContext`, `CertifyKey`, `DestroyContext`).
  * Enforce strict privilege level boundaries: operations initiated by PL1 callers must never corrupt, access, or affect PL0 context handles, measurements, or certificate configurations.
  * Context handles must be generated via cryptographically secure RNG to prevent handle guessing.
  * Context corruption must fail closed (transition context to `Inactive` or lock DPE).

### 3.2. Cryptographic & Side-Channel Vulnerabilities (Information Disclosure)
* **Threat**: Leaking private keys or intermediate CDIs during signature generation or key derivation.
* **Security Requirements**:
  * Zeroize sensitive key material and ephemeral buffers immediately after use.
  * Constant-time execution for cryptographic signing and key derivation primitives.
  * No secret-dependent branching or memory indexing in cryptographic paths.

### 3.3. Memory Safety & Buffer Parsing (Tampering / DoS)
* **Threat**: Malformed command packets overflowing response buffers or triggering panics/out-of-bounds reads in no-std firmware.
* **Security Requirements**:
  * Strict bounds checking on all command input buffers and ASN.1 serialized output structures.
  * Production firmware builds must be panic-free (`panic-check-checker` enforcement).
  * Strict bounds checking on X.509 certificate generation buffers.

### 3.4. State Transition & Replay Attacks
* **Threat**: Replaying stale context handles or attempting operations on uninitialized / destroyed contexts.
* **Security Requirements**:
  * Enforce strict finite state machine (FSM) transitions for context lifecycle.
  * Context handle rotation must atomically invalidate previous handle values.
  * Rollback and replay prevention for certificate chains and measurement logs.

---

## 4. Components Out of Direct Firmware Audit Scope
* **Test Code & Test Fixtures (General)**: All unit tests, integration tests, test harnesses, fuzzers, and test mocks across all packages are strictly out of audit scope.
* **Verification Test Suites & Go Client ABI (`verification/`)**: Functional compliance test suites.
* **Mock Rust Cryptography & Simulator Drivers (`simulator/`, `platform/src/rustcrypto.rs`)**: Mock crypto stubs used solely for simulation/unit testing rather than production hardware RoT deployment.
* Hardware-level silicon timing attacks on raw external pins (addressed at ASIC level).
* Host operating system vulnerabilities external to the DPE mailbox interface.
