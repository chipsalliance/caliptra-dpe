# Licensed under the Apache-2.0 license

import pytest
import subprocess
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from dice_extensions import MultiTcbInfo, TCG_DICE_MULTI_TCB_INFO, TCG_DICE_UEID
from enum import IntEnum
import hashlib

class DpeProfile(IntEnum):
    P256_SHA256 = 3
    P384_SHA384 = 4
    MLDSA_87 = 5

@pytest.fixture(scope="function", params=[True, False])
def sample_dpe_cert(request):
    is_critical = request.param
    profile_env = os.environ.get("DPE_PROFILE", "p384")
    if profile_env == "ml-dsa":
        profile_enum = DpeProfile.MLDSA_87
    elif profile_env == "p256":
        profile_enum = DpeProfile.P256_SHA256
    else:
        profile_enum = DpeProfile.P384_SHA384

    # Run the sample_dpe_cert tool
    # Need to run it relative to the root of the repo
    repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
    args = [
        "cargo", "run",
        "--manifest-path", "tools/Cargo.toml",
        "--bin", "sample_dpe_cert",
        "--features", profile_env,
        "--no-default-features",
        "--", "x509"
    ]
    
    if is_critical:
        args.append("--critical")
        
    result = subprocess.run(args, cwd=repo_root, capture_output=True, text=True, check=True)
    
    # Extract the PEM string from the output
    pem_output = result.stdout
    cert = x509.load_pem_x509_certificate(pem_output.encode("utf-8"))
    
    return cert, profile_enum, is_critical

def _verify_issuer_and_subject(cert, expected_issuer_name, expected_subject_cn):
    assert cert.issuer.rfc4514_string() == expected_issuer_name
    assert f'CN={expected_subject_cn}' in cert.subject.rfc4514_string()

def _verify_extensions(cert, is_ca, is_critical):
    bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc_ext.value.ca == is_ca
    assert bc_ext.critical

    ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
    if is_ca:
        assert ku_ext.value.key_cert_sign
        assert ku_ext.value.digital_signature
    else:
        assert ku_ext.value.digital_signature
        assert not ku_ext.value.key_cert_sign
    assert ku_ext.critical

    eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    if is_ca:
        assert x509.ObjectIdentifier("2.23.133.5.4.100.12") in eku_ext.value # tcg-dice-kp-eca
    else:
        assert x509.ObjectIdentifier("2.23.133.5.4.100.9") in eku_ext.value # tcg-dice-kp-attestLoc
    assert eku_ext.critical

    ueid_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(TCG_DICE_UEID))
    assert ueid_ext.critical == is_critical
    
    multi_tcb_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(TCG_DICE_MULTI_TCB_INFO))
    assert multi_tcb_ext.critical == is_critical

def verify_certificate(cert, is_ca, expected_issuer_name, expected_subject_cn, is_critical):
    _verify_issuer_and_subject(cert, expected_issuer_name, expected_subject_cn)
    _verify_extensions(cert, is_ca, is_critical)

def test_certify_key_strict(sample_dpe_cert):
    cert, profile, is_critical = sample_dpe_cert

    verify_certificate(cert, is_ca=False, 
                       expected_issuer_name="CN=DPE Test Alias",
                       expected_subject_cn="DPE Leaf",
                       is_critical=is_critical)

    # Verify TcbInfo
    multi_tcb_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(TCG_DICE_MULTI_TCB_INFO))
    multi_tcb_parsed = MultiTcbInfo.load(multi_tcb_ext.value.value)
    
    # There should be two TcbInfos: one for the initial context, one for the derived one.
    assert len(multi_tcb_parsed) == 2
    
    hash_size = 32 if profile == DpeProfile.P256_SHA256 else 48
    
    # First TcbInfo (initial context)
    assert multi_tcb_parsed[0]['fwids'][0]['digest'].native == (b'\0' * hash_size)

    # Second TcbInfo (derived context) should have our TCI data
    tci_data = (b'\0' * hash_size)
    assert multi_tcb_parsed[1]['fwids'][0]['digest'].native == tci_data
    
    if profile == DpeProfile.P256_SHA256:
        hasher = hashlib.sha256()
    else:
        hasher = hashlib.sha384()
        
    hasher.update(b'\0' * hash_size)
    hasher.update(tci_data)
    cumulative = hasher.digest()
