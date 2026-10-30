// Licensed under the Apache-2.0 license
#![allow(unexpected_cfgs)]

use anyhow::{anyhow, Context, Result};
pub use caliptra_dpe_dice_asn1::{Fwid, IntegrityRegister, TcbInfo, Ueid};
use std::fmt::Write;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use x509_parser::certificate::X509Certificate;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::ParsedExtension as X509ParsedExtension;
use x509_parser::prelude::FromDer;

// OIDs for DICE Extensions
const TCG_DICE_TCB_INFO_OID: &str = "2.23.133.5.4.1";
const TCG_DICE_MULTI_TCB_INFO_OID: &str = "2.23.133.5.4.5";
const TCG_DICE_UEID_OID: &str = "2.23.133.5.4.4";
const TCG_DICE_KP_IDENTITY_INIT_OID: &str = "2.23.133.5.4.100.6";
const TCG_DICE_KP_IDENTITY_LOC_OID: &str = "2.23.133.5.4.100.7";
const TCG_DICE_KP_ATTEST_INIT_OID: &str = "2.23.133.5.4.100.8";
const TCG_DICE_KP_ATTEST_LOC_OID: &str = "2.23.133.5.4.100.9";
const TCG_DICE_KP_ECA_OID: &str = "2.23.133.5.4.100.12";
const TCG_STORAGE_HPKE_OID: &str = "2.23.133.21.1.1";

pub const DEFAULT_SAMPLE_PEM: &str = include_str!(concat!(env!("OUT_DIR"), "/sample_cert.pem"));

#[derive(Debug, Clone)]
pub struct ParsedFwid {
    pub hash_alg: String,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ParsedIntegrityRegister {
    pub name: Option<String>,
    pub num: Option<u64>,
    pub digests: Vec<ParsedFwid>,
}

#[derive(Debug, Clone)]
pub struct ParsedTcbInfo {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub version: Option<String>,
    pub svn: Option<u64>,
    pub layer: Option<u64>,
    pub index: Option<u64>,
    pub fwids: Vec<ParsedFwid>,
    pub flags: Option<String>,
    pub flags_bytes: Option<Vec<u8>>,
    pub vendor_info: Option<Vec<u8>>,
    pub tci_type: Option<Vec<u8>>,
    pub operational_flags_mask: Option<String>,
    pub operational_flags_mask_bytes: Option<Vec<u8>>,
    pub integrity_registers: Vec<ParsedIntegrityRegister>,
    /// Non-empty when the ASN.1 encoding of this `DiceTcbInfo` violates the
    /// TCG DICE specification (e.g. EXPLICIT context tags instead of IMPLICIT)
    /// and was recovered only via a lenient fallback parser.
    pub encoding_warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedExtension {
    pub oid: String,
    pub name: String,
    pub critical: bool,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct ParsedCert {
    pub is_csr: bool,
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub signature_algorithm: String,
    pub not_before: String,
    pub not_after: String,
    pub public_key_info: String,
    pub profile: String,
    pub ueid: Option<Vec<u8>>,
    pub subject_key_id: Option<Vec<u8>>,
    pub authority_key_id: Option<Vec<u8>>,
    pub tcb_infos: Vec<ParsedTcbInfo>,
    pub extensions: Vec<ParsedExtension>,
}

fn format_tci_type(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    if !bytes.is_empty() && bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return format!("0x{} ('{}')", hex, s);
        }
    }
    format!("0x{}", hex)
}

fn format_tci_type_short(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    if !bytes.is_empty() && bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        if let Ok(s) = std::str::from_utf8(bytes) {
            if bytes.len() <= 4 {
                return format!("0x{} ('{}')", hex, s);
            } else {
                return format!("'{}'", s);
            }
        }
    }
    format!("0x{}", format_bytes_brief(bytes, 16))
}

fn format_svn(svn: u64) -> String {
    if (0x0100..=0x01ff).contains(&svn) {
        format!("{} (0x{:04x} fixed-width)", svn & 0xff, svn)
    } else {
        svn.to_string()
    }
}

fn format_operational_flags(b: &asn1::BitString) -> String {
    let bytes = b.as_bytes();
    let hex = hex::encode(bytes);
    let mut active_flags = Vec::new();
    if let Some(&b0) = bytes.first() {
        if (b0 & 0x80) != 0 {
            active_flags.push("notConfigured");
        }
        if (b0 & 0x40) != 0 {
            active_flags.push("notSecure");
        }
        if (b0 & 0x20) != 0 {
            active_flags.push("recovery");
        }
        if (b0 & 0x10) != 0 {
            active_flags.push("debug");
        }
    }
    if bytes.len() >= 4 && (bytes[3] & 0x01) != 0 {
        active_flags.push("fixedWidth");
    }
    if active_flags.is_empty() {
        format!("0x{}", hex)
    } else {
        format!("0x{} ({})", hex, active_flags.join(", "))
    }
}

fn format_bytes_brief(bytes: &[u8], max_len: usize) -> String {
    let hex = hex::encode(bytes);
    if hex.len() > max_len {
        format!("{}...", &hex[..max_len])
    } else {
        hex
    }
}

fn extract_cn(dn: &str) -> String {
    for part in dn.split(',') {
        let trimmed = part.trim();
        if let Some(cn) = trimmed.strip_prefix("CN=") {
            return cn.trim().to_string();
        }
    }
    dn.to_string()
}

fn oid_friendly_name(oid_str: &str) -> String {
    match oid_str {
        "2.16.840.1.101.3.4.2.1" => "SHA-256 (2.16.840.1.101.3.4.2.1)".to_string(),
        "2.16.840.1.101.3.4.2.2" => "SHA-384 (2.16.840.1.101.3.4.2.2)".to_string(),
        "2.16.840.1.101.3.4.2.3" => "SHA-512 (2.16.840.1.101.3.4.2.3)".to_string(),
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87 (2.16.840.1.101.3.4.3.19)".to_string(),
        "2.16.840.1.101.3.4.4.3" => "ML-KEM-1024 (2.16.840.1.101.3.4.4.3)".to_string(),
        "1.3.6.1.5.5.7.6.63" => "ML-KEM-1024-ECDH-P384 (1.3.6.1.5.5.7.6.63)".to_string(),
        "1.2.840.10045.2.1" => "ecPublicKey".to_string(),
        "1.2.840.10045.3.1.7" => "secp256r1 (P-256)".to_string(),
        "1.3.132.0.34" => "secp384r1 (P-384)".to_string(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".to_string(),
        TCG_DICE_TCB_INFO_OID => "tcg-dice-TcbInfo".to_string(),
        TCG_DICE_MULTI_TCB_INFO_OID => "tcg-dice-MultiTcbInfo".to_string(),
        TCG_DICE_UEID_OID => "tcg-dice-Ueid".to_string(),
        TCG_DICE_KP_IDENTITY_INIT_OID => "tcg-dice-kp-identityInit".to_string(),
        TCG_DICE_KP_IDENTITY_LOC_OID => "tcg-dice-kp-identityLoc".to_string(),
        TCG_DICE_KP_ATTEST_INIT_OID => "tcg-dice-kp-attestInit".to_string(),
        TCG_DICE_KP_ATTEST_LOC_OID => "tcg-dice-kp-attestLoc".to_string(),
        TCG_DICE_KP_ECA_OID => "tcg-dice-kp-eca".to_string(),
        TCG_STORAGE_HPKE_OID => "tcg-storage-hpke".to_string(),
        "2.5.29.19" => "basicConstraints".to_string(),
        "2.5.29.15" => "keyUsage".to_string(),
        "2.5.29.37" => "extendedKeyUsage".to_string(),
        "2.5.29.14" => "subjectKeyIdentifier".to_string(),
        "2.5.29.35" => "authorityKeyIdentifier".to_string(),
        "2.5.29.17" => "subjectAltName".to_string(),
        _ => oid_str.to_string(),
    }
}

/// Converts any of the `TcbInfo`-shaped structs (`TcbInfo`, `ExplicitTcbInfo`,
/// `LegacyTcbInfo`) into a `ParsedTcbInfo`. The structs share field names but
/// are distinct types, so a macro is used instead of a trait to avoid
/// duplicating this conversion three times.
macro_rules! convert_tcb_info {
    ($tcb:expr, $mask:expr) => {{
        let tcb = $tcb;
        let mask: Option<&asn1::BitString> = $mask;

        let mut parsed_fwids = Vec::new();
        if let Some(fwids_seq) = &tcb.fwids {
            for fwid in fwids_seq.clone() {
                parsed_fwids.push(ParsedFwid {
                    hash_alg: fwid.hash_alg.to_string(),
                    digest: fwid.digest.to_vec(),
                });
            }
        }

        let mut parsed_irs = Vec::new();
        if let Some(irs_seq) = &tcb.integrity_registers {
            for ir in irs_seq.clone() {
                let mut ir_digests = Vec::new();
                if let Some(ir_fwids) = ir.register_digests {
                    for fwid in ir_fwids {
                        ir_digests.push(ParsedFwid {
                            hash_alg: fwid.hash_alg.to_string(),
                            digest: fwid.digest.to_vec(),
                        });
                    }
                }
                parsed_irs.push(ParsedIntegrityRegister {
                    name: ir.register_name.map(|s| s.as_str().to_string()),
                    num: ir.register_num,
                    digests: ir_digests,
                });
            }
        }

        ParsedTcbInfo {
            vendor: tcb.vendor.clone().map(|s| s.as_str().to_string()),
            model: tcb.model.clone().map(|s| s.as_str().to_string()),
            version: tcb.version.clone().map(|s| s.as_str().to_string()),
            svn: tcb.svn,
            layer: tcb.layer,
            index: tcb.index,
            fwids: parsed_fwids,
            flags: tcb.flags.as_ref().map(format_operational_flags),
            flags_bytes: tcb.flags.as_ref().map(|b| b.as_bytes().to_vec()),
            vendor_info: tcb.vendor_info.map(|v| v.to_vec()),
            tci_type: tcb.tci_type.map(|t| t.to_vec()),
            operational_flags_mask: mask.map(format_operational_flags),
            operational_flags_mask_bytes: mask.map(|b| b.as_bytes().to_vec()),
            integrity_registers: parsed_irs,
            encoding_warnings: Vec::new(),
        }
    }};
}

fn parse_single_tcb_info(tcb: &TcbInfo) -> ParsedTcbInfo {
    convert_tcb_info!(tcb, tcb.operational_flags_mask.as_ref())
}

const EXPLICIT_TAGGING_WARNING: &str =
    "DiceTcbInfo fields are encoded with EXPLICIT ASN.1 context tags (constructed [n] wrappers) \
     instead of the IMPLICIT tags required by the TCG DICE Attestation Architecture. \
     Strict verifiers will reject this extension; values below were recovered with a lenient parser.";

/// `DiceTcbInfo` with EXPLICIT context tags.
///
/// The TCG DICE Attestation Architecture specifies IMPLICIT tagging for
/// `DiceTcbInfo`, but some implementations emit EXPLICIT tags (a constructed
/// `[n]` wrapper around the universal-tagged inner value). This struct accepts
/// that encoding so such certificates are still displayed with their TCB
/// fields instead of failing to parse.
#[derive(asn1::Asn1Read)]
pub struct ExplicitTcbInfo<'a> {
    #[explicit(0)]
    pub vendor: Option<asn1::Utf8String<'a>>,
    #[explicit(1)]
    pub model: Option<asn1::Utf8String<'a>>,
    #[explicit(2)]
    pub version: Option<asn1::Utf8String<'a>>,
    #[explicit(3)]
    pub svn: Option<u64>,
    #[explicit(4)]
    pub layer: Option<u64>,
    #[explicit(5)]
    pub index: Option<u64>,
    #[explicit(6)]
    pub fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
    #[explicit(7)]
    pub flags: Option<asn1::BitString<'a>>,
    #[explicit(8)]
    pub vendor_info: Option<&'a [u8]>,
    #[explicit(9)]
    pub tci_type: Option<&'a [u8]>,
    #[explicit(10)]
    pub operational_flags_mask: Option<asn1::BitString<'a>>,
    #[explicit(11)]
    pub integrity_registers: Option<asn1::SequenceOf<'a, IntegrityRegister<'a>>>,
}

fn parse_explicit_tcb_info(tcb: &ExplicitTcbInfo) -> ParsedTcbInfo {
    let mut parsed = convert_tcb_info!(tcb, tcb.operational_flags_mask.as_ref());
    parsed
        .encoding_warnings
        .push(EXPLICIT_TAGGING_WARNING.to_string());
    parsed
}

#[derive(asn1::Asn1Read)]
pub struct LegacyTcbInfo<'a> {
    #[implicit(0)]
    pub vendor: Option<asn1::Utf8String<'a>>,
    #[implicit(1)]
    pub model: Option<asn1::Utf8String<'a>>,
    #[implicit(2)]
    pub version: Option<asn1::Utf8String<'a>>,
    #[implicit(3)]
    pub svn: Option<u64>,
    #[implicit(4)]
    pub layer: Option<u64>,
    #[implicit(5)]
    pub index: Option<u64>,
    #[implicit(6)]
    pub fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
    #[implicit(7)]
    pub flags: Option<asn1::BitString<'a>>,
    #[implicit(8)]
    pub vendor_info: Option<&'a [u8]>,
    #[implicit(9)]
    pub tci_type: Option<&'a [u8]>,
    #[implicit(10)]
    pub integrity_registers: Option<asn1::SequenceOf<'a, IntegrityRegister<'a>>>,
}

fn parse_legacy_tcb_info(tcb: &LegacyTcbInfo) -> ParsedTcbInfo {
    convert_tcb_info!(tcb, None)
}

struct ExtractedExtensions {
    tcb_infos: Vec<ParsedTcbInfo>,
    ueid: Option<Vec<u8>>,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    is_ca: bool,
    path_len_constraint: Option<u32>,
    extensions: Vec<ParsedExtension>,
}

fn parse_extensions<'a>(
    exts: impl Iterator<Item = &'a x509_parser::extensions::X509Extension<'a>>,
) -> ExtractedExtensions {
    let mut tcb_infos = Vec::new();
    let mut ueid = None;
    let mut subject_key_id = None;
    let mut authority_key_id = None;
    let mut is_ca = false;
    let mut path_len_constraint = None;
    let mut extensions = Vec::new();

    for ext in exts {
        let oid_str = ext.oid.to_id_string();
        let name = oid_friendly_name(&oid_str);
        let critical = ext.critical;
        let details;

        if oid_str == TCG_DICE_TCB_INFO_OID {
            if let Ok(tcb) = asn1::parse_single::<TcbInfo>(ext.value) {
                tcb_infos.push(parse_single_tcb_info(&tcb));
                details = "Single TCB Context".to_string();
            } else if let Ok(tcb) = asn1::parse_single::<LegacyTcbInfo>(ext.value) {
                tcb_infos.push(parse_legacy_tcb_info(&tcb));
                details = "Single TCB Context (Legacy)".to_string();
            } else if let Ok(tcb) = asn1::parse_single::<ExplicitTcbInfo>(ext.value) {
                tcb_infos.push(parse_explicit_tcb_info(&tcb));
                details = "⚠️ Single TCB Context — NON-CONFORMING ASN.1: EXPLICIT context tags \
                           (spec requires IMPLICIT)"
                    .to_string();
            } else {
                details = "Failed to parse TcbInfo".to_string();
            }
        } else if oid_str == TCG_DICE_MULTI_TCB_INFO_OID {
            let parsed_seq = asn1::parse_single::<asn1::SequenceOf<TcbInfo>>(ext.value)
                .map(|seq| {
                    seq.into_iter()
                        .map(|t| parse_single_tcb_info(&t))
                        .collect::<Vec<_>>()
                })
                .or_else(|_| {
                    asn1::parse_single::<&[u8]>(ext.value)
                        .and_then(asn1::parse_single::<asn1::SequenceOf<TcbInfo>>)
                        .map(|seq| {
                            seq.into_iter()
                                .map(|t| parse_single_tcb_info(&t))
                                .collect::<Vec<_>>()
                        })
                })
                .or_else(|_| {
                    asn1::parse_single::<asn1::SequenceOf<LegacyTcbInfo>>(ext.value).map(|seq| {
                        seq.into_iter()
                            .map(|t| parse_legacy_tcb_info(&t))
                            .collect::<Vec<_>>()
                    })
                })
                .or_else(|_| {
                    asn1::parse_single::<&[u8]>(ext.value)
                        .and_then(asn1::parse_single::<asn1::SequenceOf<LegacyTcbInfo>>)
                        .map(|seq| {
                            seq.into_iter()
                                .map(|t| parse_legacy_tcb_info(&t))
                                .collect::<Vec<_>>()
                        })
                })
                .or_else(|_| {
                    asn1::parse_single::<asn1::SequenceOf<ExplicitTcbInfo>>(ext.value).map(|seq| {
                        seq.into_iter()
                            .map(|t| parse_explicit_tcb_info(&t))
                            .collect::<Vec<_>>()
                    })
                });

            match parsed_seq {
                Ok(items) => {
                    let count = items.len();
                    let has_warnings = items.iter().any(|t| !t.encoding_warnings.is_empty());
                    tcb_infos.extend(items);
                    if has_warnings {
                        details = format!(
                            "⚠️ Contains {} TCB Context(s) — NON-CONFORMING ASN.1: EXPLICIT \
                             context tags (spec requires IMPLICIT)",
                            count
                        );
                    } else {
                        details = format!("Contains {} TCB Context(s)", count);
                    }
                }
                Err(e) => {
                    details = format!("Failed to parse SequenceOf<TcbInfo>: {:?}", e);
                }
            }
        } else if oid_str == TCG_DICE_UEID_OID {
            if let Ok(u) = asn1::parse_single::<Ueid>(ext.value) {
                ueid = Some(u.ueid.to_vec());
                details = format!("UEID: {}", hex::encode(u.ueid));
            } else {
                details = format!("Raw bytes: {}", hex::encode(ext.value));
            }
        } else {
            details = match ext.parsed_extension() {
                X509ParsedExtension::BasicConstraints(bc) => {
                    is_ca = bc.ca;
                    path_len_constraint = bc.path_len_constraint;
                    format!("CA: {}, PathLen: {:?}", bc.ca, bc.path_len_constraint)
                }
                X509ParsedExtension::KeyUsage(ku) => {
                    format!(
                        "DigitalSignature: {}, KeyCertSign: {}",
                        ku.digital_signature(),
                        ku.key_cert_sign()
                    )
                }
                X509ParsedExtension::ExtendedKeyUsage(eku) => {
                    let oids: Vec<String> = eku
                        .other
                        .iter()
                        .map(|o| oid_friendly_name(&o.to_id_string()))
                        .collect();
                    format!("EKU OIDs: {}", oids.join(", "))
                }
                X509ParsedExtension::SubjectKeyIdentifier(ski) => {
                    subject_key_id = Some(ski.0.to_vec());
                    format!("SKI: {}", hex::encode(ski.0))
                }
                X509ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    let mut s = String::new();
                    if let Some(key_id) = &aki.key_identifier {
                        authority_key_id = Some(key_id.0.to_vec());
                        write!(s, "KeyID: {}", hex::encode(key_id.0)).unwrap();
                    }
                    s
                }
                _ => format!("Raw length: {} bytes", ext.value.len()),
            };
        }

        extensions.push(ParsedExtension {
            oid: oid_str,
            name,
            critical,
            details,
        });
    }

    ExtractedExtensions {
        tcb_infos,
        ueid,
        subject_key_id,
        authority_key_id,
        is_ca,
        path_len_constraint,
        extensions,
    }
}

fn infer_dpe_profile(
    pk_oid: &str,
    pk_curve_oid: Option<&str>,
    sig_alg_oid: &str,
    tcb_infos: &[ParsedTcbInfo],
) -> String {
    if pk_oid == "2.16.840.1.101.3.4.3.19" || sig_alg_oid == "2.16.840.1.101.3.4.3.19" {
        return "ML-DSA-87 (PQC)".to_string();
    }

    let fwid_hash_oid = tcb_infos
        .iter()
        .find_map(|tcb| tcb.fwids.first())
        .map(|fwid| fwid.hash_alg.as_str());

    if sig_alg_oid == "1.2.840.10045.4.3.3"
        || pk_oid == "1.3.132.0.34"
        || pk_curve_oid == Some("1.3.132.0.34")
        || fwid_hash_oid == Some("2.16.840.1.101.3.4.2.2")
    {
        return "P384-SHA384".to_string();
    }

    if sig_alg_oid == "1.2.840.10045.4.3.2"
        || pk_oid == "1.2.840.10045.3.1.7"
        || pk_curve_oid == Some("1.2.840.10045.3.1.7")
        || fwid_hash_oid == Some("2.16.840.1.101.3.4.2.1")
    {
        return "P256-SHA256".to_string();
    }

    "Unknown".to_string()
}

fn parse_x509_cert(cert: &X509Certificate) -> Result<ParsedCert> {
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let serial = hex::encode(tbs.serial.to_bytes_be());
    let sig_alg_oid = cert.signature_algorithm.algorithm.to_id_string();
    let pk_oid = tbs.subject_pki.algorithm.algorithm.to_id_string();
    let pk_curve_oid = tbs
        .subject_pki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|oid| oid.to_id_string());

    let not_before = tbs.validity.not_before.to_string();
    let not_after = tbs.validity.not_after.to_string();

    let public_key_info = if let Some(curve_oid) = &pk_curve_oid {
        format!(
            "{} ({} / {})",
            pk_oid,
            oid_friendly_name(&pk_oid),
            oid_friendly_name(curve_oid)
        )
    } else {
        format!("{} ({})", pk_oid, oid_friendly_name(&pk_oid))
    };

    let extracted = parse_extensions(tbs.extensions().iter());

    let profile = infer_dpe_profile(
        &pk_oid,
        pk_curve_oid.as_deref(),
        &sig_alg_oid,
        &extracted.tcb_infos,
    );

    Ok(ParsedCert {
        is_csr: false,
        is_ca: extracted.is_ca,
        path_len_constraint: extracted.path_len_constraint,
        subject,
        issuer,
        serial,
        signature_algorithm: oid_friendly_name(&sig_alg_oid),
        not_before,
        not_after,
        public_key_info,
        profile,
        ueid: extracted.ueid,
        subject_key_id: extracted.subject_key_id,
        authority_key_id: extracted.authority_key_id,
        tcb_infos: extracted.tcb_infos,
        extensions: extracted.extensions,
    })
}

fn parse_csr(csr: &X509CertificationRequest) -> Result<ParsedCert> {
    let cri = &csr.certification_request_info;

    let subject = cri.subject.to_string();
    let issuer = "N/A (CSR)".to_string();
    let serial = "N/A (CSR)".to_string();
    let sig_alg_oid = csr.signature_algorithm.algorithm.to_id_string();
    let pk_oid = cri.subject_pki.algorithm.algorithm.to_id_string();
    let pk_curve_oid = cri
        .subject_pki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|oid| oid.to_id_string());

    let not_before = "N/A (CSR)".to_string();
    let not_after = "N/A (CSR)".to_string();

    let public_key_info = if let Some(curve_oid) = &pk_curve_oid {
        format!(
            "{} ({} / {})",
            pk_oid,
            oid_friendly_name(&pk_oid),
            oid_friendly_name(curve_oid)
        )
    } else {
        format!("{} ({})", pk_oid, oid_friendly_name(&pk_oid))
    };

    let csr_exts = csr
        .certification_request_info
        .iter_attributes()
        .filter_map(|attr| match attr.parsed_attribute() {
            x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(req) => {
                Some(req.extensions.iter())
            }
            _ => None,
        })
        .flatten();

    let extracted = parse_extensions(csr_exts);

    let profile = infer_dpe_profile(
        &pk_oid,
        pk_curve_oid.as_deref(),
        &sig_alg_oid,
        &extracted.tcb_infos,
    );

    Ok(ParsedCert {
        is_csr: true,
        is_ca: extracted.is_ca,
        path_len_constraint: extracted.path_len_constraint,
        subject,
        issuer,
        serial,
        signature_algorithm: oid_friendly_name(&sig_alg_oid),
        not_before,
        not_after,
        public_key_info,
        profile,
        ueid: extracted.ueid,
        subject_key_id: extracted.subject_key_id,
        authority_key_id: extracted.authority_key_id,
        tcb_infos: extracted.tcb_infos,
        extensions: extracted.extensions,
    })
}

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::Decode;

fn unwrap_raw_bytes(mut bytes: &[u8]) -> Vec<u8> {
    // 1. DPE Response Header ("REPD" magic = 0x52, 0x45, 0x50, 0x44).
    // Candidate header lengths before the DER certificate/chain payload:
    // - 16:   GetCertificateChainResp (12B ResponseHdr + 4B cert_size)
    // - 80:   DeriveContextExportedCdiResp
    // - 96:   CertifyKeyP256Resp
    // - 128:  CertifyKeyP384Resp
    // - 2624: CertifyKeyMldsa87Resp
    if bytes.len() > 16 && &bytes[..4] == b"REPD" {
        for &hdr_len in &[16usize, 128, 96, 80, 2624] {
            if bytes.len() > hdr_len && bytes[hdr_len] == 0x30 {
                let size_bytes: [u8; 4] = bytes[hdr_len - 4..hdr_len].try_into().unwrap();
                let cert_size = u32::from_le_bytes(size_bytes) as usize;
                if cert_size > 0 && hdr_len + cert_size <= bytes.len() {
                    bytes = &bytes[hdr_len..hdr_len + cert_size];
                } else {
                    bytes = &bytes[hdr_len..];
                }
                break;
            }
        }
    }

    // 2. CMS SignedData / ContentInfo wrapper
    if let Ok(content_info) = ContentInfo::from_der(bytes) {
        if let Ok(signed_data) = content_info.content.decode_as::<SignedData>() {
            if let Some(encap) = signed_data.encap_content_info.econtent {
                return encap.value().to_vec();
            }
        }
    }

    bytes.to_vec()
}

fn parse_der_stream(bytes: &[u8]) -> Result<Vec<ParsedCert>> {
    let raw_der = unwrap_raw_bytes(bytes);
    let mut rem: &[u8] = &raw_der;
    let mut certs = Vec::new();

    while !rem.is_empty() {
        // Ignore trailing zero padding (e.g., from fixed-size GetCertificateChainResp buffers)
        if rem.iter().all(|&b| b == 0) {
            break;
        }

        if let Ok((next_rem, cert)) = X509Certificate::from_der(rem) {
            if next_rem.len() < rem.len() {
                certs.push(parse_x509_cert(&cert)?);
                rem = next_rem;
                continue;
            }
        }

        if let Ok((next_rem, csr)) = X509CertificationRequest::from_der(rem) {
            if next_rem.len() < rem.len() {
                certs.push(parse_csr(&csr)?);
                rem = next_rem;
                continue;
            }
        }

        break;
    }

    if certs.is_empty() {
        return Err(anyhow!(
            "Input could not be parsed as an X.509 Certificate or Certificate Signing Request (CSR)"
        ));
    }

    Ok(certs)
}

fn is_parent_of(parent: &ParsedCert, child: &ParsedCert) -> bool {
    if parent.is_csr {
        return false;
    }
    if let (Some(ski), Some(aki)) = (&parent.subject_key_id, &child.authority_key_id) {
        if ski == aki {
            // Avoid matching self-signed cert as its own child
            if parent.subject == child.subject && parent.serial == child.serial {
                return false;
            }
            return true;
        }
    }
    if !child.is_csr && !parent.subject.is_empty() && parent.subject == child.issuer {
        // Avoid matching self-signed cert as its own child
        if parent.subject == child.subject && parent.serial == child.serial {
            return false;
        }
        return true;
    }
    false
}

/// Orders a slice of parsed certificates from Root (e.g., IDevID / LDevID) to Leaf (e.g., DPE Leaf / CSR).
pub fn order_cert_chain(certs: Vec<ParsedCert>) -> Vec<ParsedCert> {
    let n = certs.len();
    if n <= 1 {
        return certs;
    }

    // For each cert i, find its issuer/parent index in `certs` if present.
    let mut parent_of: Vec<Option<usize>> = vec![None; n];
    for child_idx in 0..n {
        for cand_idx in 0..n {
            if child_idx != cand_idx && is_parent_of(&certs[cand_idx], &certs[child_idx]) {
                parent_of[child_idx] = Some(cand_idx);
                break;
            }
        }
    }

    let mut visited = vec![false; n];
    let mut ordered = Vec::with_capacity(n);

    // Find roots: certificates that have no parent in `certs` (excluding CSRs unless all are CSRs).
    let mut roots: Vec<usize> = (0..n)
        .filter(|&i| parent_of[i].is_none() && !certs[i].is_csr)
        .collect();

    // Sort roots so higher path_len_constraint (closer to root CA) comes first.
    roots.sort_by(|&a, &b| b_path_rank(&certs[b]).cmp(&b_path_rank(&certs[a])));

    for root in roots {
        let mut curr = Some(root);
        while let Some(idx) = curr {
            if visited[idx] {
                break;
            }
            visited[idx] = true;
            ordered.push(certs[idx].clone());
            // Find next unvisited child whose parent is `idx`
            curr = (0..n).find(|&c| !visited[c] && parent_of[c] == Some(idx));
        }
    }

    // Append any remaining unvisited non-CSR certs, then CSRs at the leaf end.
    for i in 0..n {
        if !visited[i] && !certs[i].is_csr {
            visited[i] = true;
            ordered.push(certs[i].clone());
        }
    }
    for i in 0..n {
        if !visited[i] {
            visited[i] = true;
            ordered.push(certs[i].clone());
        }
    }

    ordered
}

fn b_path_rank(cert: &ParsedCert) -> (bool, u32) {
    (cert.is_ca, cert.path_len_constraint.unwrap_or(0))
}

pub fn parse_cert_chain_bytes(bytes: &[u8]) -> Result<Vec<ParsedCert>> {
    let has_pem = bytes.windows(10).any(|w| w == b"-----BEGIN");
    let mut certs = Vec::new();

    if has_pem {
        let pems = ::pem::parse_many(bytes).context("Failed to parse PEM input")?;
        if pems.is_empty() {
            return Err(anyhow!("No valid PEM blocks found in input"));
        }
        for p in pems {
            let parsed = parse_der_stream(p.contents())?;
            certs.extend(parsed);
        }
    } else {
        certs = parse_der_stream(bytes)?;
    }

    Ok(order_cert_chain(certs))
}

pub fn parse_cert_bytes(bytes: &[u8]) -> Result<ParsedCert> {
    let has_pem = bytes.windows(10).any(|w| w == b"-----BEGIN");
    if has_pem {
        let p = ::pem::parse(bytes).context("Failed to parse PEM input")?;
        let mut certs = parse_der_stream(p.contents())?;
        return Ok(certs.remove(0));
    }
    let mut certs = parse_der_stream(bytes)?;
    Ok(certs.remove(0))
}

pub fn generate_mermaid_graph(cert: &ParsedCert) -> String {
    let mut out = String::new();

    writeln!(out, "```mermaid").unwrap();
    writeln!(out, "graph TD").unwrap();
    writeln!(
        out,
        "    classDef rootStyle fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#f8fafc;"
    )
    .unwrap();
    writeln!(
        out,
        "    classDef derivedStyle fill:#0f172a,stroke:#8b5cf6,stroke-width:2px,color:#f8fafc;"
    )
    .unwrap();
    writeln!(
        out,
        "    classDef certStyle fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#f8fafc;"
    )
    .unwrap();
    writeln!(
        out,
        "    classDef warnStyle fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#fde68a;"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "    subgraph Derivation_Chain [TCB Context Derivation Chain]"
    )
    .unwrap();
    writeln!(out, "        direction TD").unwrap();

    let num_tcbs = cert.tcb_infos.len();

    for (i, tcb) in cert.tcb_infos.iter().enumerate() {
        let is_root = i == 0;
        let has_warn = !tcb.encoding_warnings.is_empty();
        let warn_prefix = if has_warn { "⚠️ " } else { "" };
        let title = if is_root {
            format!("{}TCB Context {} (Root/Initial)", warn_prefix, i)
        } else {
            format!("{}TCB Context {}", warn_prefix, i)
        };

        let tci_type = tcb
            .tci_type
            .as_deref()
            .map(format_tci_type_short)
            .unwrap_or_else(|| "N/A".to_string());

        let svn = tcb.svn.map(format_svn).unwrap_or_else(|| "N/A".to_string());

        let digest = if let Some(fwid) = tcb.fwids.first() {
            format_bytes_brief(&fwid.digest, 16)
        } else if let Some(flags) = &tcb.flags {
            format!("Flags: {}", flags)
        } else {
            "N/A".to_string()
        };

        let class = if has_warn {
            ":::warnStyle"
        } else if is_root {
            ":::rootStyle"
        } else {
            ":::derivedStyle"
        };

        let warn_line = if has_warn {
            "<br/>⚠️ Non-conforming ASN.1"
        } else {
            ""
        };

        writeln!(
            out,
            "        NODE{}[\"<b>{}</b><br/>Type: <code>{}</code><br/>SVN: {}<br/>Digest: <code>{}</code>{}\"]{}",
            i,
            title,
            tci_type.replace('"', "'"),
            svn.replace('"', "'"),
            digest.replace('"', "'"),
            warn_line,
            class
        )
        .unwrap();

        if i > 0 {
            writeln!(out, "        NODE{} --> NODE{}", i - 1, i).unwrap();
        }
    }

    let cert_title = cert_role_title(cert);

    let cert_id = num_tcbs;
    let cert_label = if cert.issuer.starts_with("N/A") {
        format!(
            "<b>{}</b><br/>Subject: {}",
            cert_title,
            cert.subject.replace('"', "'")
        )
    } else {
        format!(
            "<b>{}</b><br/>Subject: {}<br/>Issuer: {}",
            cert_title,
            cert.subject.replace('"', "'"),
            cert.issuer.replace('"', "'")
        )
    };
    writeln!(
        out,
        "        NODE{}[\"{}\"]:::certStyle",
        cert_id, cert_label
    )
    .unwrap();

    if num_tcbs > 0 {
        writeln!(out, "        NODE{} --> NODE{}", num_tcbs - 1, cert_id).unwrap();
    }

    writeln!(out, "    end").unwrap();
    writeln!(out, "```").unwrap();

    out
}

fn cert_role_title(cert: &ParsedCert) -> String {
    if cert.is_csr {
        if cert.tcb_infos.is_empty() {
            "Certificate Signing Request (CSR - 0 TCB Contexts)".to_string()
        } else {
            "Certificate Signing Request (CSR)".to_string()
        }
    } else if cert.is_ca {
        match cert.path_len_constraint {
            Some(pl) => format!("CA Certificate (pathlen: {})", pl),
            None => "CA Certificate".to_string(),
        }
    } else if cert.tcb_infos.is_empty() {
        "Identity / CA Certificate (0 TCB Contexts)".to_string()
    } else {
        "Leaf / Alias Certificate".to_string()
    }
}

pub fn generate_chain_mermaid_graph(certs: &[ParsedCert]) -> String {
    if certs.len() == 1 {
        return generate_mermaid_graph(&certs[0]);
    }

    let mut out = String::new();

    writeln!(out, "```mermaid").unwrap();
    writeln!(out, "graph TD").unwrap();
    writeln!(
        out,
        "    classDef rootStyle fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#f8fafc;"
    )
    .unwrap();
    writeln!(
        out,
        "    classDef derivedStyle fill:#0f172a,stroke:#8b5cf6,stroke-width:2px,color:#f8fafc;"
    )
    .unwrap();
    writeln!(
        out,
        "    classDef caCertStyle fill:#1e3a8a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;"
    )
    .unwrap();
    writeln!(
        out,
        "    classDef certStyle fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#f8fafc;"
    )
    .unwrap();
    writeln!(
        out,
        "    classDef warnStyle fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#fde68a;"
    )
    .unwrap();
    writeln!(out).unwrap();

    for (c_idx, cert) in certs.iter().enumerate() {
        let short_cn = extract_cn(&cert.subject).replace('"', "'");
        writeln!(
            out,
            "    subgraph STAGE_{} [\"Stage {}: {}\"]",
            c_idx, c_idx, short_cn
        )
        .unwrap();
        writeln!(out, "        direction TD").unwrap();

        let num_tcbs = cert.tcb_infos.len();
        for (t_idx, tcb) in cert.tcb_infos.iter().enumerate() {
            let is_root = c_idx == 0 && t_idx == 0;
            let has_warn = !tcb.encoding_warnings.is_empty();
            let title = if has_warn {
                format!("⚠️ TCB Context {}", t_idx)
            } else {
                format!("TCB Context {}", t_idx)
            };

            let tci_type = tcb
                .tci_type
                .as_deref()
                .map(format_tci_type_short)
                .unwrap_or_else(|| "N/A".to_string());

            let svn = tcb.svn.map(format_svn).unwrap_or_else(|| "N/A".to_string());

            let digest = if let Some(fwid) = tcb.fwids.first() {
                format_bytes_brief(&fwid.digest, 16)
            } else if let Some(flags) = &tcb.flags {
                format!("Flags: {}", flags)
            } else {
                "N/A".to_string()
            };

            let class = if has_warn {
                ":::warnStyle"
            } else if is_root {
                ":::rootStyle"
            } else {
                ":::derivedStyle"
            };

            let warn_line = if has_warn {
                "<br/>⚠️ Non-conforming ASN.1"
            } else {
                ""
            };

            writeln!(
                out,
                "        C{}_TCB{}[\"<b>{}</b><br/>Type: <code>{}</code><br/>SVN: {}<br/>Digest: <code>{}</code>{}\"]{}",
                c_idx,
                t_idx,
                title,
                tci_type.replace('"', "'"),
                svn.replace('"', "'"),
                digest.replace('"', "'"),
                warn_line,
                class
            )
            .unwrap();

            if t_idx > 0 {
                writeln!(
                    out,
                    "        C{}_TCB{} --> C{}_TCB{}",
                    c_idx,
                    t_idx - 1,
                    c_idx,
                    t_idx
                )
                .unwrap();
            }
        }

        let role_title = cert_role_title(cert);
        let cert_label = if cert.issuer.starts_with("N/A") {
            format!(
                "<b>{}</b><br/>Subject: {}",
                role_title,
                extract_cn(&cert.subject).replace('"', "'")
            )
        } else {
            format!(
                "<b>{}</b><br/>Subject: {}<br/>Issuer: {}",
                role_title,
                extract_cn(&cert.subject).replace('"', "'"),
                extract_cn(&cert.issuer).replace('"', "'")
            )
        };
        let cert_class = if cert.is_ca {
            ":::caCertStyle"
        } else {
            ":::certStyle"
        };

        writeln!(
            out,
            "        C{}_CERT[\"{}\"]{}",
            c_idx, cert_label, cert_class
        )
        .unwrap();

        if num_tcbs > 0 {
            writeln!(
                out,
                "        C{}_TCB{} --> C{}_CERT",
                c_idx,
                num_tcbs - 1,
                c_idx
            )
            .unwrap();
        }

        writeln!(out, "    end").unwrap();

        if c_idx > 0 {
            let next_entry = if num_tcbs > 0 {
                format!("C{}_TCB0", c_idx)
            } else {
                format!("C{}_CERT", c_idx)
            };
            writeln!(out, "    C{}_CERT --> {}", c_idx - 1, next_entry).unwrap();
        }
    }

    writeln!(out, "```").unwrap();
    out
}

fn write_cert_details(
    out: &mut String,
    cert: &ParsedCert,
    heading_prefix: &str,
    include_mermaid: bool,
) {
    writeln!(out, "{} Certificate Overview\n", heading_prefix).unwrap();
    writeln!(out, "| Attribute | Value |").unwrap();
    writeln!(out, "| :--- | :--- |").unwrap();
    writeln!(out, "| **Subject** | `{}` |", cert.subject).unwrap();
    writeln!(out, "| **Issuer** | `{}` |", cert.issuer).unwrap();
    writeln!(out, "| **Serial Number** | `{}` |", cert.serial).unwrap();
    writeln!(
        out,
        "| **Signature Algorithm** | {} |",
        cert.signature_algorithm
    )
    .unwrap();
    if !cert.is_csr {
        writeln!(
            out,
            "| **Validity** | {} to {} |",
            cert.not_before, cert.not_after
        )
        .unwrap();
    }
    writeln!(out, "| **Public Key** | {} |", cert.public_key_info).unwrap();
    writeln!(out, "| **Inferred DPE Profile** | `{}` |", cert.profile).unwrap();

    if let Some(ueid_bytes) = &cert.ueid {
        if ueid_bytes.len() == 17 {
            writeln!(
                out,
                "| **UEID** | `{}`<br/>*(Type: `0x{:02x}`, 128-bit Fuse UEID: `{}`)* |",
                hex::encode(ueid_bytes),
                ueid_bytes[0],
                hex::encode(&ueid_bytes[1..])
            )
            .unwrap();
        } else {
            writeln!(out, "| **UEID** | `{}` |", hex::encode(ueid_bytes)).unwrap();
        }
    }
    writeln!(out).unwrap();

    if include_mermaid {
        writeln!(out, "{} TCB Context Graph\n", heading_prefix).unwrap();
        let mermaid = generate_mermaid_graph(cert);
        writeln!(out, "{}\n", mermaid).unwrap();
    }

    if !cert.tcb_infos.is_empty() {
        writeln!(out, "{} TCB Contexts Breakdown\n", heading_prefix).unwrap();
        for (i, tcb) in cert.tcb_infos.iter().enumerate() {
            let title = if i == 0 {
                format!("{}# TCB Context {} (Root/Initial)\n", heading_prefix, i)
            } else {
                format!("{}# TCB Context {}\n", heading_prefix, i)
            };
            writeln!(out, "{}", title).unwrap();
            for warning in &tcb.encoding_warnings {
                writeln!(out, "> ⚠️ **ASN.1 Encoding Warning:** {}\n", warning).unwrap();
            }
            writeln!(out, "| Field | Value |").unwrap();
            writeln!(out, "| :--- | :--- |").unwrap();
            writeln!(
                out,
                "| **Index** | {} |",
                tcb.index.map_or("N/A".to_string(), |idx| idx.to_string())
            )
            .unwrap();
            writeln!(
                out,
                "| **Layer** | {} |",
                tcb.layer.map_or("N/A".to_string(), |l| l.to_string())
            )
            .unwrap();
            writeln!(
                out,
                "| **TCI Type** | {} |",
                tcb.tci_type
                    .as_deref()
                    .map(format_tci_type)
                    .unwrap_or_else(|| "N/A".to_string())
            )
            .unwrap();
            writeln!(
                out,
                "| **SVN** | {} |",
                tcb.svn.map_or("N/A".to_string(), format_svn)
            )
            .unwrap();
            writeln!(
                out,
                "| **Vendor** | {} |",
                tcb.vendor.as_deref().unwrap_or("N/A")
            )
            .unwrap();
            writeln!(
                out,
                "| **Model** | {} |",
                tcb.model.as_deref().unwrap_or("N/A")
            )
            .unwrap();
            writeln!(
                out,
                "| **Version** | {} |",
                tcb.version.as_deref().unwrap_or("N/A")
            )
            .unwrap();
            if let Some(vi) = &tcb.vendor_info {
                writeln!(out, "| **Vendor Info** | `{}` |", hex::encode(vi)).unwrap();
            }
            if let Some(flags) = &tcb.flags {
                writeln!(out, "| **Flags** | `{}` |", flags).unwrap();
            }
            if let Some(op_flags) = &tcb.operational_flags_mask {
                writeln!(out, "| **Operational Flags Mask** | `{}` |", op_flags).unwrap();
            }
            writeln!(out).unwrap();

            if !tcb.fwids.is_empty() {
                writeln!(out, "{}## FWIDs / Measurements", heading_prefix).unwrap();
                writeln!(out).unwrap();
                for fwid in &tcb.fwids {
                    let alg_name = oid_friendly_name(&fwid.hash_alg);
                    writeln!(out, "- **Algorithm**: {}", alg_name).unwrap();
                    writeln!(out, "  - **Digest**: `{}`", hex::encode(&fwid.digest)).unwrap();
                }
                writeln!(out).unwrap();
            }

            write_caliptra_measured_values_section(out, tcb, cert, heading_prefix);

            if !tcb.integrity_registers.is_empty() {
                writeln!(out, "{}## Integrity Registers", heading_prefix).unwrap();
                writeln!(out).unwrap();
                for ir in &tcb.integrity_registers {
                    writeln!(
                        out,
                        "- **Register Num**: {}",
                        ir.num.map_or("N/A".to_string(), |n| n.to_string())
                    )
                    .unwrap();
                    if let Some(name) = &ir.name {
                        writeln!(out, "  - **Name**: {}", name).unwrap();
                    }
                    for fwid in &ir.digests {
                        writeln!(
                            out,
                            "  - **Digest ({})**: `{}`",
                            oid_friendly_name(&fwid.hash_alg),
                            hex::encode(&fwid.digest)
                        )
                        .unwrap();
                    }
                }
                writeln!(out).unwrap();
            }
        }
    }

    let ext_title = if cert.is_csr {
        format!("{} Requested Extensions", heading_prefix)
    } else {
        format!("{} X.509 Certificate Extensions", heading_prefix)
    };
    writeln!(out, "{}", ext_title).unwrap();
    writeln!(out, "| Extension | Critical | Details / Value |").unwrap();
    writeln!(out, "| :--- | :---: | :--- |").unwrap();
    for ext in &cert.extensions {
        writeln!(
            out,
            "| **{}**<br/>`{}` | {} | {} |",
            ext.name,
            ext.oid,
            if ext.critical { "Yes" } else { "No" },
            ext.details
        )
        .unwrap();
    }
    writeln!(out).unwrap();
}

fn decode_flags_lifecycle_and_debug(flags_bytes: Option<&[u8]>) -> Option<(u8, &'static str, u8)> {
    let b0 = *flags_bytes?.first()?;
    let not_configured = (b0 & 0x80) != 0;
    let not_secure = (b0 & 0x40) != 0;
    let debug_unlocked = (b0 & 0x10) != 0;

    let (lifecycle_val, lifecycle_name) = if not_configured {
        (0u8, "Unprovisioned (0)")
    } else if not_secure {
        (1u8, "Manufacturing (1)")
    } else {
        (3u8, "Production (3)")
    };

    let debug_locked_val = if debug_unlocked { 0u8 } else { 1u8 };
    Some((lifecycle_val, lifecycle_name, debug_locked_val))
}

fn write_caliptra_measured_values_section(
    out: &mut String,
    tcb: &ParsedTcbInfo,
    cert: &ParsedCert,
    heading_prefix: &str,
) {
    let Some(tci_bytes) = tcb.tci_type.as_deref() else {
        return;
    };
    let digest_hex = tcb
        .fwids
        .first()
        .map(|f| hex::encode(&f.digest))
        .unwrap_or_default();

    match tci_bytes {
        b"DEVICE_INFO" => {
            let fuse_svn = tcb.svn.map(|s| s & 0xff);
            let lc_dbg = decode_flags_lifecycle_and_debug(tcb.flags_bytes.as_deref());
            writeln!(
                out,
                "{}## Decoded Fuse & Device Values (`DEVICE_INFO` — Caliptra 1.x)",
                heading_prefix
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(
                out,
                "| Fuse / Device Field | Decoded Value | Source in Caliptra ROM |"
            )
            .unwrap();
            writeln!(out, "| :--- | :--- | :--- |").unwrap();
            if let Some(svn) = fuse_svn {
                writeln!(
                    out,
                    "| **FMC Effective Fuse SVN** | **`{}`** *(encoded as `0x{:04x}`)* | `fw_proc_info.fmc_effective_fuse_svn` (`FUSE_FMC_KEY_MANIFEST_SVN`) |",
                    svn,
                    tcb.svn.unwrap_or(0)
                )
                .unwrap();
            }
            if let Some((lc_val, lc_name, dbg_locked)) = lc_dbg {
                writeln!(
                    out,
                    "| **Device Lifecycle (Fuse)** | **`{}`** | `soc_ifc.lifecycle()` (decoded from `Flags` bits 0–1) |",
                    lc_name
                )
                .unwrap();
                writeln!(
                    out,
                    "| **Debug Locked State** | **`{} ({})`** | `soc_ifc.debug_locked()` (decoded from `Flags` bit 3) |",
                    if dbg_locked == 1 {
                        "Locked"
                    } else {
                        "Unlocked"
                    },
                    dbg_locked
                )
                .unwrap();
                let _ = lc_val;
            }
            if let Some(ueid) = &cert.ueid {
                if ueid.len() == 17 {
                    writeln!(
                        out,
                        "| **UEID Fuse (128-bit)** | `{}` *(Type `0x{:02x}`)* | `soc_ifc.fuse_bank().ueid()` |",
                        hex::encode(&ueid[1..]),
                        ueid[0]
                    )
                    .unwrap();
                }
            }
            writeln!(out).unwrap();

            writeln!(
                out,
                "{}## FWID SHA-384 Preimage Layout (103 Bytes Hashed into `DEVICE_INFO`)",
                heading_prefix
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(
                out,
                "| Byte Offset | Field | Size | Value / Status | ROM Source (`fmc_alias.rs`) |"
            )
            .unwrap();
            writeln!(out, "| :---: | :--- | :---: | :--- | :--- |").unwrap();
            let lc_str = lc_dbg
                .map(|(_, name, _)| format!("**`{}`** *(known from Flags)*", name))
                .unwrap_or_else(|| "Hashed (`0..=3`)".to_string());
            let dbg_str = lc_dbg
                .map(|(_, _, dbg)| format!("**`{}`** *(known from Flags)*", dbg))
                .unwrap_or_else(|| "Hashed (`0..=1`)".to_string());
            writeln!(
                out,
                "| `0` | `lifecycle` | 1 B | {} | `env.soc_ifc.lifecycle() as u8` |",
                lc_str
            )
            .unwrap();
            writeln!(
                out,
                "| `1` | `debug_locked` | 1 B | {} | `env.soc_ifc.debug_locked() as u8` |",
                dbg_str
            )
            .unwrap();
            writeln!(
                out,
                "| `2` | `anti_rollback_disable` | 1 B | Hashed (`0` or `1`) | `env.soc_ifc.fuse_bank().anti_rollback_disable() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `3` | `ecc_vendor_pk_index` | 1 B | Hashed (`0..15`) | `env.data_vault.ecc_vendor_pk_index() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `4` | `lms_vendor_pk_index` | 1 B | Hashed (`0..31` / `0xFF`) | `env.data_vault.lms_vendor_pk_index() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `5` | `lms_verify` | 1 B | Hashed (`0` or `1`) | `env.soc_ifc.fuse_bank().lms_verify() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `6` | `owner_pub_keys_digest_in_fuses` | 1 B | Hashed (`0` or `1`) | `fw_proc_info.owner_pub_keys_digest_in_fuses as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `7..55` | `vendor_pub_key_hash` | 48 B | Hashed (SHA-384) | `env.soc_ifc.fuse_bank().vendor_pub_key_hash()` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `55..103` | `owner_pk_hash` | 48 B | Hashed (SHA-384) | `env.data_vault.owner_pk_hash()` |"
            )
            .unwrap();
            writeln!(out).unwrap();
        }
        b"FMC_INFO" => {
            let fmc_svn = tcb.svn.map(|s| s & 0xff);
            writeln!(
                out,
                "{}## Decoded Measurement Info (`FMC_INFO` — Caliptra 1.x)",
                heading_prefix
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Field | Decoded Value | Source in Caliptra ROM |").unwrap();
            writeln!(out, "| :--- | :--- | :--- |").unwrap();
            if let Some(svn) = fmc_svn {
                writeln!(
                    out,
                    "| **FMC Image Manifest SVN** | **`{}`** *(encoded as `0x{:04x}`)* | `env.data_vault.fmc_svn()` (Manifest Header SVN) |",
                    svn,
                    tcb.svn.unwrap_or(0)
                )
                .unwrap();
            }
            writeln!(
                out,
                "| **FMC TCI Digest** | `{}` | `env.data_vault.fmc_tci()` (SHA-384 of FMC image from signed manifest TOC) |",
                digest_hex
            )
            .unwrap();
            writeln!(out).unwrap();
        }
        b"RT_INFO" => {
            let rt_svn = tcb.svn.map(|s| s & 0xff);
            writeln!(
                out,
                "{}## Decoded Measurement Info (`RT_INFO` — Caliptra 1.x)",
                heading_prefix
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Field | Decoded Value | Source in Caliptra FMC |").unwrap();
            writeln!(out, "| :--- | :--- | :--- |").unwrap();
            if let Some(svn) = rt_svn {
                writeln!(
                    out,
                    "| **Runtime Firmware SVN** | **`{}`** *(encoded as `0x{:04x}`)* | `env.data_vault.rt_svn()` (Manifest Header SVN) |",
                    svn,
                    tcb.svn.unwrap_or(0)
                )
                .unwrap();
            }
            writeln!(
                out,
                "| **Runtime TCI Digest** | `{}` | `env.data_vault.rt_tci()` (SHA-384 of Runtime firmware image) |",
                digest_hex
            )
            .unwrap();
            writeln!(out).unwrap();
        }
        b"CALIPTRA_2_X_FUSE_OWNER_INFO" => {
            writeln!(
                out,
                "{}## FWID SHA-384 Preimage Layout (59 Bytes Hashed into `CALIPTRA_2_X_FUSE_OWNER_INFO`)",
                heading_prefix
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(
                out,
                "| Byte Offset | Field | Size | ROM Source (`gen_fmc_alias_owner_device_info_hash`) |"
            )
            .unwrap();
            writeln!(out, "| :---: | :--- | :---: | :--- |").unwrap();
            writeln!(
                out,
                "| `0..48` | `owner_pk_hash` | 48 B | `data_vault.owner_pk_hash()` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `48` | `owner_pub_keys_digest_in_fuses` | 1 B | `(soc_ifc.fuse_bank().owner_pub_key_hash() != 0) as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `49` | `anti_rollback_disable` | 1 B | `soc_ifc.fuse_bank().anti_rollback_disable() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `50` | `vendor_ecc_pub_key_revocation` | 1 B | `soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation().bits() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `51..55` | `vendor_lms_pub_key_revocation` | 4 B (LE) | `soc_ifc.fuse_bank().vendor_lms_pub_key_revocation().to_le_bytes()` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `55` | `vendor_mldsa_pub_key_revocation` | 1 B | `soc_ifc.fuse_bank().vendor_mldsa_pub_key_revocation() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `56` | `fw_fuse_svn` | 1 B | `soc_ifc.fuse_bank().fw_fuse_svn() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `57` | `soc_manifest_fuse_svn` | 1 B | `soc_ifc.fuse_bank().soc_manifest_fuse_svn() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `58` | `max_soc_manifest_fuse_svn` | 1 B | `soc_ifc.fuse_bank().max_soc_manifest_fuse_svn() as u8` |"
            )
            .unwrap();
            writeln!(out).unwrap();
        }
        b"CALIPTRA_2_X_FUSE_VENDOR_INFO" => {
            let inferred_fw_svn = cert
                .tcb_infos
                .iter()
                .find(|t| {
                    t.tci_type.as_deref() == Some(b"CALIPTRA_2_X_FMC_FIRMWARE_INFO".as_slice())
                })
                .and_then(|t| t.svn)
                .map(|s| s & 0xff);
            writeln!(
                out,
                "{}## FWID SHA-384 Preimage Layout (54–55 Bytes Hashed into `CALIPTRA_2_X_FUSE_VENDOR_INFO`)",
                heading_prefix
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(
                out,
                "| Byte Offset | Field | Size | Value / Status | ROM Source (`gen_fmc_alias_vendor_device_info_hash`) |"
            )
            .unwrap();
            writeln!(out, "| :---: | :--- | :---: | :--- | :--- |").unwrap();
            writeln!(
                out,
                "| `0..48` | `vendor_pub_key_info_hash` | 48 B | Hashed (SHA-384) | `soc_ifc.fuse_bank().vendor_pub_key_info_hash()` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `48` | `pqc_key_type` | 1 B | Hashed (`1` = ML-DSA, `3` = LMS) | `soc_ifc.fuse_bank().pqc_key_type() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `49` | `lifecycle` | 1 B | Hashed (`0..=3`) | `soc_ifc.lifecycle() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `50` | `debug_locked` | 1 B | Hashed (`0` or `1`) | `soc_ifc.debug_locked() as u8` |"
            )
            .unwrap();
            let svn_status = inferred_fw_svn
                .map(|s| format!("**`{}`** *(from `CALIPTRA_2_X_FMC_FIRMWARE_INFO.svn`)*", s))
                .unwrap_or_else(|| "Hashed (`u8`)".to_string());
            writeln!(
                out,
                "| `51` | `cold_boot_fw_svn` | 1 B | {} | `data_vault.cold_boot_fw_svn() as u8` |",
                svn_status
            )
            .unwrap();
            writeln!(
                out,
                "| `52` | `vendor_ecc_pk_index` | 1 B | Hashed (`0..15`) | `data_vault.vendor_ecc_pk_index() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `53` | `vendor_pqc_pk_index` | 1 B | Hashed (`0..31`) | `data_vault.vendor_pqc_pk_index() as u8` |"
            )
            .unwrap();
            writeln!(
                out,
                "| `54` | `subsystem_mode` *(ROM >= 2.1.3)* | 1 B | Hashed (`0` or `1`) | `soc_ifc.subsystem_mode() as u8` |"
            )
            .unwrap();
            writeln!(out).unwrap();
        }
        b"CALIPTRA_2_X_FMC_FIRMWARE_INFO" => {
            let fmc_svn = tcb.svn.map(|s| s & 0xff);
            writeln!(
                out,
                "{}## Decoded Measurement Info (`CALIPTRA_2_X_FMC_FIRMWARE_INFO` — Caliptra 2.x)",
                heading_prefix
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Field | Decoded Value | Source in Caliptra ROM |").unwrap();
            writeln!(out, "| :--- | :--- | :--- |").unwrap();
            if let Some(svn) = fmc_svn {
                writeln!(
                    out,
                    "| **Cold Boot FW SVN** | **`{}`** *(encoded as `0x{:04x}`)* | `data_vault.cold_boot_fw_svn()` |",
                    svn,
                    tcb.svn.unwrap_or(0)
                )
                .unwrap();
            }
            writeln!(
                out,
                "| **FMC TCI Digest** | `{}` | `data_vault.fmc_tci()` (SHA-384 of FMC image) |",
                digest_hex
            )
            .unwrap();
            writeln!(out).unwrap();
        }
        b"CALIPTRA_2_X_RT_FIRMWARE_INFO" => {
            let rt_svn = tcb.svn.map(|s| s & 0xff);
            writeln!(
                out,
                "{}## Decoded Measurement Info (`CALIPTRA_2_X_RT_FIRMWARE_INFO` — Caliptra 2.x)",
                heading_prefix
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Field | Decoded Value | Source in Caliptra FMC |").unwrap();
            writeln!(out, "| :--- | :--- | :--- |").unwrap();
            if let Some(svn) = rt_svn {
                writeln!(
                    out,
                    "| **Runtime FW SVN** | **`{}`** *(encoded as `0x{:04x}`)* | `data_vault.rt_svn()` |",
                    svn,
                    tcb.svn.unwrap_or(0)
                )
                .unwrap();
            }
            writeln!(
                out,
                "| **Runtime TCI Digest** | `{}` | `data_vault.rt_tci()` (SHA-384 of Runtime image) |",
                digest_hex
            )
            .unwrap();
            writeln!(out).unwrap();
        }
        _ => {}
    }
}

pub fn generate_markdown(cert: &ParsedCert) -> String {
    let mut out = String::new();

    let doc_title = if cert.is_csr {
        "# DPE Certificate Signing Request (CSR) TCB Context Analysis"
    } else {
        "# DPE Certificate TCB Context Analysis"
    };

    writeln!(out, "{}\n", doc_title).unwrap();
    write_chain_encoding_warnings(&mut out, std::slice::from_ref(cert));
    write_cert_details(&mut out, cert, "##", true);

    out
}

fn write_chain_encoding_warnings(out: &mut String, certs: &[ParsedCert]) {
    let mut warned_stages = Vec::new();
    for (idx, cert) in certs.iter().enumerate() {
        let mut msgs = Vec::new();
        for tcb in &cert.tcb_infos {
            for w in &tcb.encoding_warnings {
                if !msgs.contains(&w.as_str()) {
                    msgs.push(w.as_str());
                }
            }
        }
        if !msgs.is_empty() {
            warned_stages.push((idx, extract_cn(&cert.subject), msgs));
        }
    }
    if warned_stages.is_empty() {
        return;
    }

    writeln!(
        out,
        "> ⚠️ **Non-Conforming ASN.1 Encoding Detected** — {} certificate(s) contain \
         `DiceTcbInfo` extensions that violate the TCG DICE specification. The visualizer \
         recovered the fields below for inspection, but strict verifiers will reject them:",
        warned_stages.len()
    )
    .unwrap();
    for (idx, cn, msgs) in warned_stages {
        for msg in msgs {
            writeln!(out, "> - **Stage {} (`{}`):** {}", idx, cn, msg).unwrap();
        }
    }
    writeln!(out).unwrap();
}

pub fn generate_chain_markdown(certs: &[ParsedCert]) -> String {
    if certs.len() == 1 {
        return generate_markdown(&certs[0]);
    }

    let mut out = String::new();
    writeln!(
        out,
        "# DPE Certificate Chain TCB Context Analysis ({} Certificates)\n",
        certs.len()
    )
    .unwrap();

    write_chain_encoding_warnings(&mut out, certs);

    writeln!(out, "## Certificate Chain Summary\n").unwrap();
    writeln!(
        out,
        "| Stage | Role / Type | Subject | Issuer | Inferred DPE Profile | TCB Contexts |"
    )
    .unwrap();
    writeln!(out, "| :---: | :--- | :--- | :--- | :--- | :--- |").unwrap();

    for (idx, cert) in certs.iter().enumerate() {
        let tcb_summary = if cert.tcb_infos.is_empty() {
            "0".to_string()
        } else {
            let has_warn = cert
                .tcb_infos
                .iter()
                .any(|t| !t.encoding_warnings.is_empty());
            let types: Vec<String> = cert
                .tcb_infos
                .iter()
                .map(|t| {
                    t.tci_type
                        .as_deref()
                        .and_then(|b| std::str::from_utf8(b).ok())
                        .map(|s| format!("`{}`", s))
                        .unwrap_or_else(|| "TCB".to_string())
                })
                .collect();
            let suffix = if has_warn {
                " ⚠️ *non-conforming ASN.1*"
            } else {
                ""
            };
            format!("{} ({}){}", cert.tcb_infos.len(), types.join(", "), suffix)
        };
        writeln!(
            out,
            "| **{}** | {} | `{}` | `{}` | `{}` | {} |",
            idx,
            cert_role_title(cert),
            extract_cn(&cert.subject),
            extract_cn(&cert.issuer),
            cert.profile,
            tcb_summary
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "## Full Chain TCB Context Graph\n").unwrap();
    let chain_mermaid = generate_chain_mermaid_graph(certs);
    writeln!(out, "{}\n", chain_mermaid).unwrap();

    for (idx, cert) in certs.iter().enumerate() {
        writeln!(out, "---\n").unwrap();
        writeln!(
            out,
            "## Stage {}: {} ({})\n",
            idx,
            extract_cn(&cert.subject),
            cert_role_title(cert)
        )
        .unwrap();
        write_cert_details(&mut out, cert, "###", false);
    }

    out
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn render_dpe_cert_markdown(cert_input: &[u8]) -> Result<String, JsValue> {
    let parsed_chain =
        parse_cert_chain_bytes(cert_input).map_err(|e| JsValue::from_str(&format!("{:#}", e)))?;
    Ok(generate_chain_markdown(&parsed_chain))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn get_default_sample_pem() -> String {
    DEFAULT_SAMPLE_PEM.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALIPTRA_1_X_CHAIN_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIHbzCCBvagAwIBAgIUODdGRDM0RDNDMzkyOUNCNDc5N0UwCgYIKoZIzj0EAwMwazEeMBwGA1UEAwwVQ2FsaXB0cmEgMS4wIFJ0IEFsaWFzMUkwRwYDVQQFE0A0NTk1RTA5QUFDNDQ3RkMyMTVEQjQzQ0NFMkEwNEUwQURDNDRBQkZCMjg4MkI3QUZFNjQ4QjExNzg5MjExMkRGMCIYDzIwMjMwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMF4xETAPBgNVBAMTCERQRSBMZWFmMUkwRwYDVQQFE0A4N0ZEMzREM0MzOTI5Q0I0Nzk3RTEwMUU5MkY4QUE5QkREQTY2NEUyNjg3RDI5MEEwNjBEQjcxQjBFQjY2MDM1MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsX/CZK1Y+lhYJLZPW88xRenWORcslbFvyZpFzbLeaFIWhzJO/DkrJp4iY8VEpQDagxM61NprdYRSeJoNzLNpNfKOyfjo2Ka4zk3ao3ePLEe7yJo2Bi8eDHZstukDA2DKo4IFYjCCBV4wggS7BgZngQUFBAUBAQAEggSsMIIEqDCBkqY/MD0GCWCGSAFlAwQCAgQw/78Wgt0V6dfam0bEV5QBCpAtxshOO8oVD/p5z6x/9dJbqJnA4m7R5HiMY4TiyMXliAT/////iQRNSlRSqkMwQaI/MD0GCWCGSAFlAwQCAgQwoEvHyZ109nm+9lj7H1S2ld8IAp7xLHUe0db3SjJgvsxbqXQ/DWfChQ0hvTkJb1qPMIGSpj8wPQYJYIZIAWUDBAICBDB0vAuKEguYFOf239aRQhZPFztGn1ErYewczCOBm7WSg6arsPALpj1F0aL9Q5vNof2IBAAAAACJBFBWQk2qQzBBoj8wPQYJYIZIAWUDBAICBDA9DxbwV1l89pq0OJXCb5Q2uu5XZeenwe1JlF/JmRc0kxR/TLfcGC4FPt1HDm5oERgwgZKmPzA9BglghkgBZQMEAgIEMBCCKiFsJJ+Y6Pqw7HBaQtqP0koIQUtszRhEPR32bMzFLrgcUocyIyyiz85KKi7kqIgEAAAAAIkEQjFSRqpDMEGiPzA9BglghkgBZQMEAgIEMDjbesJ1Zw1QeFGcL5v+w/wovqusIFuYFQA3NfdAkcso3A9gMesCP14nTTRgV1U9FTCBkqY/MD0GCWCGSAFlAwQCAgQwPKcxkCvmjjYHpP48e85p49TH202doOSbKSyVjIT9FaRVIgCVD0lcInySeATha/fOiAQAAAAAiQRCMVJTqkMwQaI/MD0GCWCGSAFlAwQCAgQwZmgWtahlC7VGbCmVhG09lN4AP565QbM378iw9uHmhxXiOBMDEc/f6dki/Gk5+tYEMIGSpj8wPQYJYIZIAWUDBAICBDDwN7Ky0MmugQCEJniSOj1LE3q/Fvk6/gc83tfInFYFP6EKIk4qEtsyn3M6IkZej06IBAAAAACJBEIyU0aqQzBBoj8wPQYJYIZIAWUDBAICBDAmU0jBcbbQwwO8KzjZg2E5EBUfZ3UfLwmRnDKTlGkvjttIBA+yEBJX2uugNJa1RGswgZKmPzA9BglghkgBZQMEAgIEMIr7pfUZ7rFkkY36lQpWDIHh0wKKkv/4Sn7yGgHqdApTRtJbDIK7bGwAv+dX483laIgEAAAAAIkEQjJTU6pDMEGiPzA9BglghkgBZQMEAgIEMDUu9gfKI92n9qHt4gaMAcDcEQhQ3IvscMRRpPhoj6hxK3mDYlm3zZvI/aQh4TOXrDCBkqY/MD0GCWCGSAFlAwQCAgQwheGq85OXRgRVp13cU+k0z9A/kZMOAJUE0o5kosk/bSQ0V2MbVmPZwsl4x+GHXT11iAQAAAAAiQRIQjBDqkMwQaI/MD0GCWCGSAFlAwQCAgQwey3nXPxEGaqj81sPcvMqCFx9H3YaiubTwKwWjnFZsOrPUAM0fA1fXHm8m2SAp/5nMIGSpj8wPQYJYIZIAWUDBAICBDAi5FbBJk55q26cjH4ykzL5en2825NlJ0dv7x5atHuNBNg6tpW5dMaC3MJqogcXW72IBAAAAACJBEhCMFOqQzBBoj8wPQYJYIZIAWUDBAICBDALrkCP5TX9+PoOl/0CirGIEtf2cgg0bLlWycFmJ6IYJZvEMs70DNYFxwgy6nGu+WwwQQYGZ4EFBQQEAQEABDQwMgQwemL8nMGe3801zG13dbAuQipBQuaFOVNXiQ53OOhFg1GQsGrAdr9KsU714ZTBf8QfMA8GA1UdEwEB/wQFMAMBAQAwDgYDVR0PAQH/BAQDAgeAMBUGA1UdJQEB/wQLMAkGB2eBBQUEZAkwIgYDVR0jAQEABBgwFoAURZXgmqxEf8IV20PM4qBOCtxEq/swCgYIKoZIzj0EAwMDZwAwZAIwQtPuRowN7L+4n/eHTRmJbTBqyyMDs6DzAmWtJTCV3kBq8EsxzjaG0pvqhxSnH6QlAjBnyfMJgsQ0UeT0ChKSYjMZI3QG/7TIJTFNs19jqBeb13bbCTlmwWOF/2f4nOjCF6E=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC/jCCAoWgAwIBAgIURZXgmqxEf8IV20PM4qBOCtxEq/swCgYIKoZIzj0EAwMwbDEfMB0GA1UEAwwWQ2FsaXB0cmEgMS4wIEZNQyBBbGlhczFJMEcGA1UEBRNAMjZGODVENEFGNEE0MEUxQTY4QUE0QzkzMDkxMTRGREFGQ0UxM0U4NTEyRkQ0MTIyMDY0NTc5Njk2RkZCNUE2NjAiGA8yMDIzMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjBrMR4wHAYDVQQDDBVDYWxpcHRyYSAxLjAgUnQgQWxpYXMxSTBHBgNVBAUTQDQ1OTVFMDlBQUM0NDdGQzIxNURCNDNDQ0UyQTA0RTBBREM0NEFCRkIyODgyQjdBRkU2NDhCMTE3ODkyMTEyREYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT3YQiAy1tWvAIbLEL/Oq90NnqHauxvw2XA3MiZzMWX7LCK2rNULhHVT6QvMNY8tvKDx2cIiAjAS45QTF3dVrkYmZZNviXX6aIV9QLIy/j0WcwEAqN3Lf5X2Y8/M+eWDxqjgeQwgeEwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAoQwHwYGZ4EFBQQEBBUwEwQRAQAAAAAAAAAAAAAAAAAAAAAwWgYGZ4EFBQQBBFAwToMCAQGmPzA9BglghkgBZQMEAgIEMImGXgdJFUfs+m2piX7f0cCoGoFDRi2WKMWs8+aWt4V68xqCSSpR4bZzSiTQFWHUhIkHUlRfSU5GTzAdBgNVHQ4EFgQURZXgmqxEf8IV20PM4qBOCtxEq/swHwYDVR0jBBgwFoAUJvhdSvSkDhpoqkyTCRFP2vzhPoUwCgYIKoZIzj0EAwMDZwAwZAIwLHtGrn3+zIL4vx1+Epm3McbYxOT2b0BOG71cl3XXUQRCcONDoH6YNw5mrL/q4NU5AjB8uKmxbdh6nNUyIa2ufN4iiHFKmVHSW/NoLud7xd+uJc/y8Yj6+N2+xMX+t24pv2I=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDZjCCAu2gAwIBAgIUJvhdSvSkDhpoqkyTCRFP2vzhPoUwCgYIKoZIzj0EAwMwaTEcMBoGA1UEAwwTQ2FsaXB0cmEgMS4wIExEZXZJRDFJMEcGA1UEBRNAQ0IxNDkyNzAzQUE3QzQwRUREMTk4QUQyREI1MTVDQTcyMzk4OTRCMTFBMzdBNUZDQTQ5NTRBMzU3MjQ3MUE0MTAiGA8yMDIzMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjBsMR8wHQYDVQQDDBZDYWxpcHRyYSAxLjAgRk1DIEFsaWFzMUkwRwYDVQQFE0AyNkY4NUQ0QUY0QTQwRTFBNjhBQTRDOTMwOTExNEZEQUZDRTEzRTg1MTJGRDQxMjIwNjQ1Nzk2OTZGRkI1QTY2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVw5EVwLV707RrLElKQGyl56yxDKHsQFPP29N0SzGa6md2SSNllj1K/wRmwetJWV4HtJYRQfra/XmbT4CzhqH19MfeaciOyjUoYYzYtGGH8pA3Ttr9hv5ivm2T6z6Y7qxo4IBTTCCAUkwEgYDVR0TAQH/BAgwBgEB/wIBAzAOBgNVHQ8BAf8EBAMCAgQwHwYGZ4EFBQQEBBUwEwQRAQAAAAAAAAAAAAAAAAAAAAAwgcEGBmeBBQUEBQSBtjCBszBggwIBAaY/MD0GCWCGSAFlAwQCAgQwi6enbmO9Br0eaWzTt8jtR7+irc6y6wtDKRwaNw70HPKl5VpsOsNhu7fBCxNR2LCXhwUAAAAAAYkLREVWSUNFX0lORk+KBQDQAAABME+DAgEBpj8wPQYJYIZIAWUDBAICBDAhzWGnZZvOqLm5/3vZGBvuTEZxyeeqJNZ7cnvfHK4Um5iD4USYavjTcZXv+bqanlGJCEZNQ19JTkZPMB0GA1UdDgQWBBQm+F1K9KQOGmiqTJMJEU/a/OE+hTAfBgNVHSMEGDAWgBTLFJJwOqfEDt0ZitLbUVynI5iUsTAKBggqhkjOPQQDAwNnADBkAjASZ1B/KTQ6U4W1FlXO/aqGhsJg1NWfr9F47TJZh++ohykk468Pg7hciV7purfjr2ECMFidC1g7TP1CkQrJux5stC8E5//UKpM1uZpwqVH6O1yFtyvUi38/z10PFoArf4UuKA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICnjCCAiSgAwIBAgIUTxSScDqnxA7dGYrS21FcpyOYlLEwCgYIKoZIzj0EAwMwaTEcMBoGA1UEAwwTQ2FsaXB0cmEgMS4wIElEZXZJRDFJMEcGA1UEBRNAQUM2NzdBMTdEN0E5MEU4QjUwMTA4MEJBOURENDQyODQxNkVCNDQwMTMwNkNBN0ExRDhBMzNFNTlFQjk5NTk5MTAiGA8yMDIzMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjBpMRwwGgYDVQQDDBNDYWxpcHRyYSAxLjAgTERldklEMUkwRwYDVQQFE0BDQjE0OTI3MDNBQTdDNDBFREQxOThBRDJEQjUxNUNBNzIzOTg5NEIxMUEzN0E1RkNBNDk1NEEzNTcyNDcxQTQxMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEb2fES0PaMcDRhiQQxLHtlLXpouc9rkBaSNUPM5OEvwMLLdVvSvOIh+IqYI25SqyXaf+lkuuF6KIbcoAslQr8b6lEn9M9wj2jGTI8jC4Aenep+CZdJJdaJKXK9GGskqrdo4GIMIGFMBIGA1UdEwEB/wQIMAYBAf8CAQQwDgYDVR0PAQH/BAQDAgIEMB8GBmeBBQUEBAQVMBMEEQEAAAAAAAAAAAAAAAAAAAAAMB0GA1UdDgQWBBTLFJJwOqfEDt0ZitLbUVynI5iUsTAfBgNVHSMEGDAWgBSKAK01CRX14dJqjkqqOwPR4A+dKjAKBggqhkjOPQQDAwNoADBlAjAZxzOPS54nd2p/B2SagnEZOR2E1UWozpt0kF5pFq98ipl/DAn2ZbNOCdxaK+5Lf48CMQD613842G+m3mfHZ7SClz2el54CanrFK8+dvlVkB0oI4bQnKhTEho7rjc0TclV/G98=
-----END CERTIFICATE-----";

    #[test]
    fn test_parse_caliptra_1_x_cert_chain() {
        let certs = parse_cert_chain_bytes(CALIPTRA_1_X_CHAIN_PEM.as_bytes()).unwrap();
        assert_eq!(certs.len(), 4);

        // Ordered Root-to-Leaf: LDevID -> FMC Alias -> Rt Alias -> DPE Leaf
        assert_eq!(extract_cn(&certs[0].subject), "Caliptra 1.0 LDevID");
        assert_eq!(extract_cn(&certs[0].issuer), "Caliptra 1.0 IDevID");
        assert!(certs[0].is_ca);
        assert_eq!(certs[0].path_len_constraint, Some(4));
        assert_eq!(certs[0].tcb_infos.len(), 0);

        assert_eq!(extract_cn(&certs[1].subject), "Caliptra 1.0 FMC Alias");
        assert_eq!(extract_cn(&certs[1].issuer), "Caliptra 1.0 LDevID");
        assert!(certs[1].is_ca);
        assert_eq!(certs[1].path_len_constraint, Some(3));
        assert_eq!(certs[1].tcb_infos.len(), 2);
        assert_eq!(
            certs[1].tcb_infos[0].tci_type.as_deref(),
            Some(b"DEVICE_INFO".as_slice())
        );
        assert_eq!(certs[1].tcb_infos[0].svn, Some(0x0101));
        assert_eq!(
            certs[1].tcb_infos[0].flags.as_deref(),
            Some("0x00000001 (fixedWidth)")
        );
        assert_eq!(
            certs[1].tcb_infos[0].operational_flags_mask.as_deref(),
            Some("0xd0000001 (notConfigured, notSecure, debug, fixedWidth)")
        );
        assert_eq!(
            certs[1].tcb_infos[1].tci_type.as_deref(),
            Some(b"FMC_INFO".as_slice())
        );
        assert_eq!(certs[1].tcb_infos[1].svn, Some(0x0101));

        assert_eq!(extract_cn(&certs[2].subject), "Caliptra 1.0 Rt Alias");
        assert_eq!(extract_cn(&certs[2].issuer), "Caliptra 1.0 FMC Alias");
        assert!(certs[2].is_ca);
        assert_eq!(certs[2].path_len_constraint, Some(2));
        assert_eq!(certs[2].tcb_infos.len(), 1);
        assert_eq!(
            certs[2].tcb_infos[0].tci_type.as_deref(),
            Some(b"RT_INFO".as_slice())
        );
        assert_eq!(certs[2].tcb_infos[0].svn, Some(0x0101));

        assert_eq!(extract_cn(&certs[3].subject), "DPE Leaf");
        assert_eq!(extract_cn(&certs[3].issuer), "Caliptra 1.0 Rt Alias");
        assert!(!certs[3].is_ca);
        assert_eq!(certs[3].tcb_infos.len(), 8);
        assert_eq!(
            certs[3].tcb_infos[0].tci_type.as_deref(),
            Some(b"MJTR".as_slice())
        );
        assert_eq!(
            certs[3].tcb_infos[7].tci_type.as_deref(),
            Some(b"HB0S".as_slice())
        );

        let md = generate_chain_markdown(&certs);
        assert!(md.contains("# DPE Certificate Chain TCB Context Analysis (4 Certificates)"));
        assert!(md.contains("Stage 0: Caliptra 1.0 LDevID"));
        assert!(md.contains("Stage 1: Caliptra 1.0 FMC Alias"));
        assert!(md.contains("Stage 2: Caliptra 1.0 Rt Alias"));
        assert!(md.contains("Stage 3: DPE Leaf"));
        assert!(md.contains("1 (0x0101 fixed-width)"));
        assert!(md.contains("1 (0x0101 fixed-width)"));
        assert!(md.contains("C0_CERT --> C1_TCB0"));
        assert!(md.contains("C1_CERT --> C2_TCB0"));
        assert!(md.contains("C2_CERT --> C3_TCB0"));
    }

    #[test]
    fn test_concatenated_der_and_dpe_response_header() {
        let pems = ::pem::parse_many(CALIPTRA_1_X_CHAIN_PEM.as_bytes()).unwrap();
        // Build Root-to-Leaf raw DER chain (as returned by DPE GetCertificateChain)
        let mut concat_der = Vec::new();
        for p in pems.iter().rev() {
            concat_der.extend_from_slice(p.contents());
        }

        // 1. Raw concatenated DER
        let certs = parse_cert_chain_bytes(&concat_der).unwrap();
        assert_eq!(certs.len(), 4);
        assert_eq!(extract_cn(&certs[0].subject), "Caliptra 1.0 LDevID");
        assert_eq!(extract_cn(&certs[3].subject), "DPE Leaf");

        // 2. Wrapped in DPE GetCertificateChainResp header (12B ResponseHdr + 4B size + trailing 0s)
        let mut dpe_resp = Vec::new();
        dpe_resp.extend_from_slice(b"REPD");
        dpe_resp.extend_from_slice(&0u32.to_le_bytes()); // status
        dpe_resp.extend_from_slice(&0u32.to_le_bytes()); // profile
        dpe_resp.extend_from_slice(&(concat_der.len() as u32).to_le_bytes()); // certificate_size
        dpe_resp.extend_from_slice(&concat_der);
        dpe_resp.extend_from_slice(&[0u8; 64]); // trailing zero padding

        let certs_from_resp = parse_cert_chain_bytes(&dpe_resp).unwrap();
        assert_eq!(certs_from_resp.len(), 4);
        assert_eq!(
            extract_cn(&certs_from_resp[0].subject),
            "Caliptra 1.0 LDevID"
        );
        assert_eq!(extract_cn(&certs_from_resp[3].subject), "DPE Leaf");
    }

    #[test]
    fn test_parse_explicit_tagged_tcb_info() {
        // Construct a synthetic certificate whose `tcg-dice-TcbInfo` extension
        // encodes `DiceTcbInfo` with EXPLICIT context tags (constructed `[n]`
        // wrappers around universal-tagged inner values) instead of the
        // IMPLICIT tags mandated by the TCG DICE specification.
        #[derive(asn1::Asn1Write)]
        struct ExplicitTcbInfoWriter<'a> {
            #[explicit(0)]
            vendor: Option<asn1::Utf8String<'a>>,
            #[explicit(1)]
            model: Option<asn1::Utf8String<'a>>,
            #[explicit(4)]
            layer: Option<u64>,
            #[explicit(5)]
            index: Option<u64>,
            #[explicit(6)]
            fwids: Option<asn1::SequenceOfWriter<'a, caliptra_dpe_dice_asn1::FwidWriter<'a>>>,
            #[explicit(7)]
            flags: Option<asn1::BitString<'a>>,
            #[explicit(9)]
            tci_type: Option<&'a [u8]>,
        }

        let sha384_oid = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.2").unwrap();
        let digest = [0x42u8; 48];
        let fwid_items = [caliptra_dpe_dice_asn1::FwidWriter {
            hash_alg: sha384_oid,
            digest: &digest,
        }];
        let tcb_der = asn1::write_single(&ExplicitTcbInfoWriter {
            vendor: Some(asn1::Utf8String::new("ExampleVendor")),
            model: Some(asn1::Utf8String::new("ModelX")),
            layer: Some(0),
            index: Some(0),
            fwids: Some(asn1::SequenceOfWriter::new(&fwid_items)),
            flags: asn1::BitString::new(&[0x01], 0),
            tci_type: Some(b"TEST"),
        })
        .unwrap();

        // Wrap `tcb_der` into a `tcg-dice-TcbInfo` (2.23.133.5.4.1) extension
        // inside a Caliptra-style TBS template.
        let mut tcb_ext: Vec<u8> = vec![
            0x30,
            0x81,
            (13 + tcb_der.len()) as u8,
            0x06,
            6,
            0x67,
            0x81,
            0x05,
            0x05,
            0x04,
            0x01,
            0x01,
            1,
            0xff,
            0x04,
            tcb_der.len() as u8,
        ];
        tcb_ext.extend_from_slice(&tcb_der);

        let exts_seq_len = tcb_ext.len();
        let mut exts_wrapper: Vec<u8> = vec![
            0xa3,
            0x81,
            (3 + exts_seq_len) as u8,
            0x30,
            0x81,
            exts_seq_len as u8,
        ];
        exts_wrapper.extend_from_slice(&tcb_ext);

        let mut tbs_body: Vec<u8> = vec![
            160, 3, 2, 1, 2, 2, 20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 48,
            10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, // issuer: CN=Test Issuer
            48, 22, 49, 20, 48, 18, 6, 3, 85, 4, 3, 12, 11,
        ];
        tbs_body.extend_from_slice(b"Test Issuer");
        tbs_body.extend_from_slice(&[48, 34, 24, 15]);
        tbs_body.extend_from_slice(b"20230101000000Z");
        tbs_body.extend_from_slice(&[24, 15]);
        tbs_body.extend_from_slice(b"99991231235959Z");
        // subject: CN=Test Leaf
        tbs_body.extend_from_slice(&[48, 20, 49, 18, 48, 16, 6, 3, 85, 4, 3, 12, 9]);
        tbs_body.extend_from_slice(b"Test Leaf");
        // subjectPublicKeyInfo: P-384
        tbs_body.extend_from_slice(&[
            48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0,
        ]);
        tbs_body.extend_from_slice(&[0x04; 97]);
        tbs_body.extend_from_slice(&exts_wrapper);

        let mut tbs: Vec<u8> = vec![
            0x30,
            0x82,
            (tbs_body.len() >> 8) as u8,
            (tbs_body.len() & 0xff) as u8,
        ];
        tbs.extend_from_slice(&tbs_body);

        let cert_der = wrap_tbs_as_x509_der(&tbs);
        let certs = parse_cert_chain_bytes(&cert_der).unwrap();
        assert_eq!(certs.len(), 1);

        let cert = &certs[0];
        assert_eq!(extract_cn(&cert.subject), "Test Leaf");
        assert_eq!(cert.tcb_infos.len(), 1);

        let ext = cert
            .extensions
            .iter()
            .find(|e| e.oid == TCG_DICE_TCB_INFO_OID)
            .unwrap();
        assert_eq!(
            ext.details,
            "⚠️ Single TCB Context — NON-CONFORMING ASN.1: EXPLICIT context tags \
             (spec requires IMPLICIT)"
        );

        let tcb = &cert.tcb_infos[0];
        assert_eq!(tcb.encoding_warnings, vec![EXPLICIT_TAGGING_WARNING]);
        assert_eq!(tcb.vendor.as_deref(), Some("ExampleVendor"));
        assert_eq!(tcb.model.as_deref(), Some("ModelX"));
        assert_eq!(tcb.layer, Some(0));
        assert_eq!(tcb.index, Some(0));
        assert_eq!(tcb.flags.as_deref(), Some("0x01"));
        assert_eq!(tcb.tci_type.as_deref(), Some(b"TEST".as_slice()));
        assert_eq!(tcb.fwids.len(), 1);
        assert_eq!(tcb.fwids[0].hash_alg, "2.16.840.1.101.3.4.2.2");
        assert_eq!(tcb.fwids[0].digest, vec![0x42; 48]);

        // Rendered markdown surfaces the warning at the top, on the Mermaid
        // graph node, and in the TCB context breakdown.
        let md = generate_chain_markdown(&certs);
        assert!(md.contains("⚠️ **Non-Conforming ASN.1 Encoding Detected**"));
        assert!(md.contains("1 certificate(s) contain `DiceTcbInfo` extensions"));
        assert!(md.contains(":::warnStyle"));
        assert!(md.contains("⚠️ Non-conforming ASN.1"));
        assert!(md.contains("> ⚠️ **ASN.1 Encoding Warning:**"));
    }

    /// Wraps a TBS DER slice into a syntactically valid X.509 Certificate DER with ECDSA-SHA384 OID
    fn wrap_tbs_as_x509_der(tbs: &[u8]) -> Vec<u8> {
        let sig_alg_and_sig: &[u8] = &[
            // AlgorithmIdentifier: ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
            // BIT STRING: dummy ECDSA signature SEQUENCE { INTEGER 1, INTEGER 1 }
            0x03, 0x09, 0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        ];
        let body_len = tbs.len() + sig_alg_and_sig.len();
        let mut out = Vec::with_capacity(4 + body_len);
        out.push(0x30);
        if body_len < 128 {
            out.push(body_len as u8);
        } else if body_len < 256 {
            out.push(0x81);
            out.push(body_len as u8);
        } else {
            out.push(0x82);
            out.push((body_len >> 8) as u8);
            out.push((body_len & 0xff) as u8);
        }
        out.extend_from_slice(tbs);
        out.extend_from_slice(sig_alg_and_sig);
        out
    }

    #[test]
    fn test_parse_caliptra_2_x_cert_chain() {
        // Construct Caliptra 2.1 Ecc384 LDevID, FMC Alias, and Rt Alias certificates
        // matching caliptra-sw/x509 templates (with 3 TcbInfos in FMC Alias and 1 in Rt Alias)
        let mut ldevid_tbs: Vec<u8> = vec![
            48, 130, 2, 79, 160, 3, 2, 1, 2, 2, 20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 48, 112, 49, 35, 48, 33, 6, 3,
            85, 4, 3, 12, 26, 67, 97, 108, 105, 112, 116, 114, 97, 32, 50, 46, 49, 32, 69, 99, 99,
            51, 56, 52, 32, 73, 68, 101, 118, 73, 68, 49, 73, 48, 71, 6, 3, 85, 4, 5, 19, 64,
        ];
        ldevid_tbs.extend_from_slice(&[b'0'; 64]); // issuer_sn
        ldevid_tbs.extend_from_slice(&[48, 34, 24, 15]);
        ldevid_tbs.extend_from_slice(b"20230101000000Z");
        ldevid_tbs.extend_from_slice(&[24, 15]);
        ldevid_tbs.extend_from_slice(b"99991231235959Z");
        ldevid_tbs.extend_from_slice(&[
            48, 112, 49, 35, 48, 33, 6, 3, 85, 4, 3, 12, 26, 67, 97, 108, 105, 112, 116, 114, 97,
            32, 50, 46, 49, 32, 69, 99, 99, 51, 56, 52, 32, 76, 68, 101, 118, 73, 68, 49, 73, 48,
            71, 6, 3, 85, 4, 5, 19, 64,
        ]);
        ldevid_tbs.extend_from_slice(&[b'1'; 64]); // subject_sn
        ldevid_tbs.extend_from_slice(&[
            48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0,
        ]);
        ldevid_tbs.extend_from_slice(&[0x04; 97]); // public_key
        ldevid_tbs.extend_from_slice(&[
            163, 129, 165, 48, 129, 162, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1,
            255, 2, 1, 6, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 31, 6, 6, 103,
            129, 5, 5, 4, 4, 4, 21, 48, 19, 4, 17,
        ]);
        ldevid_tbs.extend_from_slice(&[0xAA; 17]); // ueid
        ldevid_tbs.extend_from_slice(&[
            48, 27, 6, 3, 85, 29, 37, 4, 20, 48, 18, 6, 7, 103, 129, 5, 5, 4, 100, 7, 6, 7, 103,
            129, 5, 5, 4, 100, 12, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20,
        ]);
        ldevid_tbs.extend_from_slice(&[0x11; 20]); // SKI = 0x11..11
        ldevid_tbs.extend_from_slice(&[48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20]);
        ldevid_tbs.extend_from_slice(&[0x00; 20]); // AKI = 0x00..00

        let mut fmc_tbs: Vec<u8> = vec![
            48, 130, 3, 146, 160, 3, 2, 1, 2, 2, 20, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 48, 112, 49, 35, 48, 33, 6,
            3, 85, 4, 3, 12, 26, 67, 97, 108, 105, 112, 116, 114, 97, 32, 50, 46, 49, 32, 69, 99,
            99, 51, 56, 52, 32, 76, 68, 101, 118, 73, 68, 49, 73, 48, 71, 6, 3, 85, 4, 5, 19, 64,
        ];
        fmc_tbs.extend_from_slice(&[b'1'; 64]); // issuer_sn
        fmc_tbs.extend_from_slice(&[48, 34, 24, 15]);
        fmc_tbs.extend_from_slice(b"20230101000000Z");
        fmc_tbs.extend_from_slice(&[24, 15]);
        fmc_tbs.extend_from_slice(b"99991231235959Z");
        fmc_tbs.extend_from_slice(&[
            48, 115, 49, 38, 48, 36, 6, 3, 85, 4, 3, 12, 29, 67, 97, 108, 105, 112, 116, 114, 97,
            32, 50, 46, 49, 32, 69, 99, 99, 51, 56, 52, 32, 70, 77, 67, 32, 65, 108, 105, 97, 115,
            49, 73, 48, 71, 6, 3, 85, 4, 5, 19, 64,
        ]);
        fmc_tbs.extend_from_slice(&[b'2'; 64]); // subject_sn
        fmc_tbs.extend_from_slice(&[
            48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0,
        ]);
        fmc_tbs.extend_from_slice(&[0x04; 97]); // public_key
        fmc_tbs.extend_from_slice(&[
            163, 130, 1, 228, 48, 130, 1, 224, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1,
            1, 255, 2, 1, 5, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 4, 48, 31, 6, 6,
            103, 129, 5, 5, 4, 4, 4, 21, 48, 19, 4, 17,
        ]);
        fmc_tbs.extend_from_slice(&[0xAA; 17]); // ueid
        fmc_tbs.extend_from_slice(&[
            48, 27, 6, 3, 85, 29, 37, 4, 20, 48, 18, 6, 7, 103, 129, 5, 5, 4, 100, 12, 6, 7, 103,
            129, 5, 5, 4, 100, 9, 48, 130, 1, 58, 6, 6, 103, 129, 5, 5, 4, 5, 4, 130, 1, 46, 48,
            130, 1, 42, 48, 95, 166, 63, 48, 61, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 4, 48,
        ]);
        fmc_tbs.extend_from_slice(&[0xCD; 48]); // owner_device_info_hash
        fmc_tbs.extend_from_slice(&[137, 28]);
        fmc_tbs.extend_from_slice(b"CALIPTRA_2_X_FUSE_OWNER_INFO");
        fmc_tbs.extend_from_slice(&[
            48, 96, 166, 63, 48, 61, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 4, 48,
        ]);
        fmc_tbs.extend_from_slice(&[0xEF; 48]); // vendor_device_info_hash
        fmc_tbs.extend_from_slice(&[137, 29]);
        fmc_tbs.extend_from_slice(b"CALIPTRA_2_X_FUSE_VENDOR_INFO");
        fmc_tbs.extend_from_slice(&[
            48, 101, 131, 2, 1, 7, // SVN = 0x0107 (fixed-width 7)
            166, 63, 48, 61, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 4, 48,
        ]);
        fmc_tbs.extend_from_slice(&[0x89; 48]); // fmc_tci
        fmc_tbs.extend_from_slice(&[137, 30]);
        fmc_tbs.extend_from_slice(b"CALIPTRA_2_X_FMC_FIRMWARE_INFO");
        fmc_tbs.extend_from_slice(&[48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20]);
        fmc_tbs.extend_from_slice(&[0x22; 20]); // SKI = 0x22..22
        fmc_tbs.extend_from_slice(&[48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20]);
        fmc_tbs.extend_from_slice(&[0x11; 20]); // AKI = 0x11..11 (links to LDevID)

        let mut rt_tbs: Vec<u8> = vec![
            48, 130, 2, 191, 160, 3, 2, 1, 2, 2, 20, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 3, 48, 115, 49, 38, 48, 36, 6,
            3, 85, 4, 3, 12, 29, 67, 97, 108, 105, 112, 116, 114, 97, 32, 50, 46, 49, 32, 69, 99,
            99, 51, 56, 52, 32, 70, 77, 67, 32, 65, 108, 105, 97, 115, 49, 73, 48, 71, 6, 3, 85, 4,
            5, 19, 64,
        ];
        rt_tbs.extend_from_slice(&[b'2'; 64]); // issuer_sn
        rt_tbs.extend_from_slice(&[48, 34, 24, 15]);
        rt_tbs.extend_from_slice(b"20230101000000Z");
        rt_tbs.extend_from_slice(&[24, 15]);
        rt_tbs.extend_from_slice(b"99991231235959Z");
        rt_tbs.extend_from_slice(&[
            48, 114, 49, 37, 48, 35, 6, 3, 85, 4, 3, 12, 28, 67, 97, 108, 105, 112, 116, 114, 97,
            32, 50, 46, 49, 32, 69, 99, 99, 51, 56, 52, 32, 82, 116, 32, 65, 108, 105, 97, 115, 49,
            73, 48, 71, 6, 3, 85, 4, 5, 19, 64,
        ]);
        rt_tbs.extend_from_slice(&[b'3'; 64]); // subject_sn
        rt_tbs.extend_from_slice(&[
            48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0,
        ]);
        rt_tbs.extend_from_slice(&[0x04; 97]); // public_key
        rt_tbs.extend_from_slice(&[
            163, 130, 1, 15, 48, 130, 1, 11, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1,
            1, 255, 2, 1, 4, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 2, 132, 48, 31, 6, 6,
            103, 129, 5, 5, 4, 4, 4, 21, 48, 19, 4, 17,
        ]);
        rt_tbs.extend_from_slice(&[0xAA; 17]); // ueid
        rt_tbs.extend_from_slice(&[
            48, 18, 6, 3, 85, 29, 37, 4, 11, 48, 9, 6, 7, 103, 129, 5, 5, 4, 100, 12, 48, 112, 6,
            6, 103, 129, 5, 5, 4, 1, 4, 102, 48, 100, 131, 2, 1,
            9, // SVN = 0x0109 (fixed-width 9)
            166, 63, 48, 61, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 4, 48,
        ]);
        rt_tbs.extend_from_slice(&[0x77; 48]); // rt_tci
        rt_tbs.extend_from_slice(&[137, 29]);
        rt_tbs.extend_from_slice(b"CALIPTRA_2_X_RT_FIRMWARE_INFO");
        rt_tbs.extend_from_slice(&[48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20]);
        rt_tbs.extend_from_slice(&[0x33; 20]); // SKI = 0x33..33
        rt_tbs.extend_from_slice(&[48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20]);
        rt_tbs.extend_from_slice(&[0x22; 20]); // AKI = 0x22..22 (links to FMC Alias)

        let ldevid_der = wrap_tbs_as_x509_der(&ldevid_tbs);
        let fmc_der = wrap_tbs_as_x509_der(&fmc_tbs);
        let rt_der = wrap_tbs_as_x509_der(&rt_tbs);

        // Pass in Leaf-to-Root order
        let pems = vec![
            ::pem::Pem::new("CERTIFICATE", rt_der),
            ::pem::Pem::new("CERTIFICATE", fmc_der),
            ::pem::Pem::new("CERTIFICATE", ldevid_der),
        ];
        let pem_bundle = ::pem::encode_many(&pems);

        let certs = parse_cert_chain_bytes(pem_bundle.as_bytes()).unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(extract_cn(&certs[0].subject), "Caliptra 2.1 Ecc384 LDevID");
        assert_eq!(
            extract_cn(&certs[1].subject),
            "Caliptra 2.1 Ecc384 FMC Alias"
        );
        assert_eq!(
            extract_cn(&certs[2].subject),
            "Caliptra 2.1 Ecc384 Rt Alias"
        );

        assert_eq!(certs[1].tcb_infos.len(), 3);
        assert_eq!(
            certs[1].tcb_infos[0].tci_type.as_deref(),
            Some(b"CALIPTRA_2_X_FUSE_OWNER_INFO".as_slice())
        );
        assert_eq!(
            certs[1].tcb_infos[1].tci_type.as_deref(),
            Some(b"CALIPTRA_2_X_FUSE_VENDOR_INFO".as_slice())
        );
        assert_eq!(
            certs[1].tcb_infos[2].tci_type.as_deref(),
            Some(b"CALIPTRA_2_X_FMC_FIRMWARE_INFO".as_slice())
        );
        assert_eq!(certs[1].tcb_infos[2].svn, Some(0x0107));

        assert_eq!(certs[2].tcb_infos.len(), 1);
        assert_eq!(
            certs[2].tcb_infos[0].tci_type.as_deref(),
            Some(b"CALIPTRA_2_X_RT_FIRMWARE_INFO".as_slice())
        );
        assert_eq!(certs[2].tcb_infos[0].svn, Some(0x0109));

        let md = generate_chain_markdown(&certs);
        assert!(md.contains("CALIPTRA_2_X_FUSE_OWNER_INFO"));
        assert!(md.contains("CALIPTRA_2_X_FUSE_VENDOR_INFO"));
        assert!(md.contains("CALIPTRA_2_X_FMC_FIRMWARE_INFO"));
        assert!(md.contains("CALIPTRA_2_X_RT_FIRMWARE_INFO"));
        assert!(md.contains("7 (0x0107 fixed-width)"));
        assert!(md.contains("9 (0x0109 fixed-width)"));
        assert!(md.contains("tcg-dice-kp-identityLoc"));
        assert!(md.contains("tcg-dice-kp-eca"));
    }

    #[test]
    fn test_single_sample_cert_backward_compat() {
        let single = parse_cert_bytes(DEFAULT_SAMPLE_PEM.as_bytes()).unwrap();
        assert_eq!(extract_cn(&single.subject), "DPE Leaf");

        let chain = parse_cert_chain_bytes(DEFAULT_SAMPLE_PEM.as_bytes()).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(generate_chain_markdown(&chain), generate_markdown(&single));
    }

    #[test]
    fn test_order_cert_chain_self_signed_root_fallback() {
        let mut base = parse_cert_bytes(DEFAULT_SAMPLE_PEM.as_bytes()).unwrap();
        base.subject_key_id = None;
        base.authority_key_id = None;

        let mut root_ca = base.clone();
        root_ca.subject = "CN=Caliptra 1.0 IDevID".to_string();
        root_ca.issuer = "CN=Caliptra 1.0 IDevID".to_string();
        root_ca.serial = "01".to_string();
        root_ca.is_ca = true;
        root_ca.path_len_constraint = None;

        let mut intermediate = base.clone();
        intermediate.subject = "CN=Caliptra 1.0 LDevID".to_string();
        intermediate.issuer = "CN=Caliptra 1.0 IDevID".to_string();
        intermediate.serial = "02".to_string();
        intermediate.is_ca = true;
        intermediate.path_len_constraint = Some(4);

        let mut leaf = base;
        leaf.subject = "CN=DPE Leaf".to_string();
        leaf.issuer = "CN=Caliptra 1.0 LDevID".to_string();
        leaf.serial = "03".to_string();
        leaf.is_ca = false;

        // Pass in Leaf -> Intermediate -> Self-Signed Root order without SKI/AKI
        let ordered = order_cert_chain(vec![leaf, intermediate, root_ca]);
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].subject, "CN=Caliptra 1.0 IDevID");
        assert_eq!(ordered[1].subject, "CN=Caliptra 1.0 LDevID");
        assert_eq!(ordered[2].subject, "CN=DPE Leaf");
    }
}
