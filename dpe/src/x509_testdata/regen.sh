#!/usr/bin/env bash
# Licensed under the Apache-2.0 license

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"

trap 'rm -rf "$WORK_DIR"' EXIT

# Fixed subject / issuer (self-signed, so subject == issuer for the cert).
# The golden tests do not assert on the subject string, so any fixed value works.
SUBJECT="/CN=DPE Leaf"
CSR_SUBJECT="/CN=DPE Leaf/serialNumber=0000"

# Fixed validity window (matches the constants used by the in-tree unit tests).
NOT_BEFORE="20230227000000Z"
NOT_AFTER="99991231235959Z"

zeros_hex() {
    local n="$1"
    printf '00%.0s' $(seq 1 "$n")
}

fixed_scalar_hex() {
    local n="$1"
    printf '11%.0s' $(seq 1 "$n")
}

# Build the tcg-dice-Ueid extension value DER.
#
# Ueid ::= SEQUENCE { ueid OCTET STRING }
#
# The golden tests require `ueid` to be an all-zero label of `hash_size` bytes
# (see dpe/src/x509.rs, mod x509::tests::golden). Prints the DER as hex.
build_ueid_der() {
    local hash_size="$1"
    local cnf="$WORK_DIR/ueid.cnf"
    local der="$WORK_DIR/ueid.der"
    cat > "$cnf" <<EOF
asn1=SEQUENCE:ueid_seq
[ueid_seq]
label=FORMAT:HEX,OCTETSTRING:$(zeros_hex "$hash_size")
EOF
    openssl asn1parse -genconf "$cnf" -out "$der" -noout >/dev/null
    xxd -p "$der" | tr -d '\n'
}

# Build the tcg-dice-MultiTcbInfo extension value DER.
#
# MultiTcbInfo ::= SEQUENCE OF TcbInfo
# TcbInfo      ::= SEQUENCE { ..., fwids [6] IMPLICIT SEQUENCE OF FWID, ... }
# FWID         ::= SEQUENCE { hashAlg OBJECT IDENTIFIER, digest OCTET STRING }
#
# The golden tests require exactly one TcbInfo carrying one FWID whose digest is
# an all-zero measurement of `hash_size` bytes. Only the `fwids` field is
# populated here; all other (optional) TcbInfo fields are omitted, which is
# sufficient for the regression assertions. Prints the DER as hex.
build_multi_tcb_der() {
    local hash_size="$1"
    local hash_alg="$2"   # OpenSSL OID short name, e.g. sha256 / sha384
    local cnf="$WORK_DIR/multi_tcb.cnf"
    local der="$WORK_DIR/multi_tcb.der"
    cat > "$cnf" <<EOF
asn1=SEQUENCE:multi_tcb
[multi_tcb]
tcbinfo0=SEQUENCE:tcbinfo_seq

[tcbinfo_seq]
# fwids [6] IMPLICIT SEQUENCE OF FWID  (0x6C = context [6], constructed)
fwids=IMPLICIT:6C,SEQUENCE:fwid_list

[fwid_list]
fwid0=SEQUENCE:fwid0_seq

[fwid0_seq]
hashAlg=OID:$hash_alg
digest=FORMAT:HEX,OCTETSTRING:$(zeros_hex "$hash_size")
EOF
    openssl asn1parse -genconf "$cnf" -out "$der" -noout >/dev/null
    xxd -p "$der" | tr -d '\n'
}

# Build a deterministic ECDSA private key (DER, no separate public key) from a
# fixed scalar; OpenSSL derives the public point. Writes to "$1" (keyfile),
# using curve "$2" (OpenSSL curve name) and scalar byte size "$3".
build_ecdsa_key() {
    local keyfile="$1"
    local curve="$2"
    local int_size="$3"
    local cnf="$WORK_DIR/ecpriv.cnf"
    cat > "$cnf" <<EOF
asn1=SEQUENCE:ec_priv
[ec_priv]
version=INTEGER:1
privateKey=FORMAT:HEX,OCTETSTRING:$(fixed_scalar_hex "$int_size")
parameters=EXPLICIT:0,OID:$curve
EOF
    openssl asn1parse -genconf "$cnf" -out "$keyfile" -noout >/dev/null
}

build_mldsa_key() {
    local keyfile="$1"
    openssl genpkey -algorithm ML-DSA-87 -provider default \
        -pkeyopt "hexseed:$(fixed_scalar_hex 32)" -out "$keyfile" >/dev/null 2>&1
}

# Generate the golden cert + CSR for one profile.
#   $1 profile label (p256 | p384 | mldsa87)
#   $2 key file (PEM or DER)
#   $3 key format form flag ("-keyform DER" or "")
#   $4 message digest flag for signing ("-sha256" / "-sha384" / "" for ML-DSA)
#   $5 deterministic signing -sigopt flag (e.g. "-sigopt nonce-type:1")
#   $6 ueid extension DER (hex)
#   $7 multi-tcb extension DER (hex)
#
# The -sigopt selects a deterministic signature so regeneration is idempotent:
#   - ECDSA:   "nonce-type:1"   -> RFC 6979 deterministic nonce
#   - ML-DSA:  "deterministic:1" -> deterministic (non-hedged) signing
# Without it, OpenSSL randomizes each signature and every run would churn the
# golden files even when nothing structural changed.
generate_profile_artifacts() {
    local profile="$1"
    local keyfile="$2"
    local keyform="$3"
    local mdflag="$4"
    local sigopt="$5"
    local ueid_hex="$6"
    local multi_tcb_hex="$7"

    local cert_pem="$WORK_DIR/${profile}_cert.pem"
    local csr_pem="$WORK_DIR/${profile}_csr.pem"
    local cert_der="$SCRIPT_DIR/golden_cert_${profile}.der"
    local csr_der="$SCRIPT_DIR/golden_csr_${profile}.der"

    # $keyform / $mdflag / $sigopt are intentionally unquoted: each expands to
    # either several distinct arguments (e.g. `-sigopt nonce-type:1`) or to no
    # arguments at all (the ML-DSA case), so word splitting is required here.
    # shellcheck disable=SC2086

    # Self-signed certificate
    openssl req -new -x509 -key "$keyfile" $keyform $mdflag $sigopt \
        -subj "$SUBJECT" \
        -set_serial 0 \
        -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
        -addext "subjectKeyIdentifier=hash" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "2.23.133.5.4.4=critical,DER:${ueid_hex}" \
        -addext "2.23.133.5.4.5=DER:${multi_tcb_hex}" \
        -out "$cert_pem" >/dev/null 2>&1
    openssl x509 -in "$cert_pem" -outform DER -out "$cert_der"

    # PKCS#10 certification request (CSR)
    openssl req -new -key "$keyfile" $keyform $mdflag $sigopt \
        -subj "$CSR_SUBJECT" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "2.23.133.5.4.4=critical,DER:${ueid_hex}" \
        -addext "2.23.133.5.4.5=DER:${multi_tcb_hex}" \
        -out "$csr_pem" >/dev/null 2>&1
    openssl req -in "$csr_pem" -outform DER -out "$csr_der"
}


regen_p256() {
    echo "p256:"
    local key="$WORK_DIR/p256.der"
    build_ecdsa_key "$key" prime256v1 32
    local ueid multi_tcb
    ueid="$(build_ueid_der 32)"
    multi_tcb="$(build_multi_tcb_der 32 sha256)"
    generate_profile_artifacts p256 "$key" "-keyform DER" "-sha256" \
        "-sigopt nonce-type:1" "$ueid" "$multi_tcb"
}

regen_p384() {
    echo "p384:"
    local key="$WORK_DIR/p384.der"
    build_ecdsa_key "$key" secp384r1 48
    local ueid multi_tcb
    ueid="$(build_ueid_der 48)"
    multi_tcb="$(build_multi_tcb_der 48 sha384)"
    generate_profile_artifacts p384 "$key" "-keyform DER" "-sha384" \
        "-sigopt nonce-type:1" "$ueid" "$multi_tcb"
}

regen_mldsa87() {
    echo "mldsa87:"
    local key="$WORK_DIR/mldsa87.pem"
    build_mldsa_key "$key"
    # ML-DSA-87 uses SHA-384 sized (48-byte) DICE measurements; the signature
    # digest is intrinsic to ML-DSA, so no -md flag is passed.
    local ueid multi_tcb
    ueid="$(build_ueid_der 48)"
    multi_tcb="$(build_multi_tcb_der 48 sha384)"
    generate_profile_artifacts mldsa87 "$key" "" "" \
        "-sigopt deterministic:1" "$ueid" "$multi_tcb"
}

main() {
    local profiles=("$@")
    if [ "${#profiles[@]}" -eq 0 ]; then
        profiles=(p256 p384 mldsa87)
    fi

    for profile in "${profiles[@]}"; do
        case "$profile" in
            p256)    regen_p256 ;;
            p384)    regen_p384 ;;
            mldsa87) regen_mldsa87 ;;
            *)
                echo "unknown profile: $profile (expected p256, p384, or mldsa87)" >&2
                exit 1
                ;;
        esac
    done
}

main "$@"
