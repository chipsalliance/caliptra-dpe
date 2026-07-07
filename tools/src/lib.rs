// Licensed under the Apache-2.0 license
#![allow(unexpected_cfgs)]

use anyhow::{anyhow, Context, Result};
#[derive(asn1::Asn1Read)]
pub struct Fwid<'a> {
    pub hash_alg: asn1::ObjectIdentifier,
    pub digest: &'a [u8],
}

#[derive(asn1::Asn1Read)]
pub struct IntegrityRegister<'a> {
    #[implicit(0)]
    pub register_name: Option<asn1::IA5String<'a>>,
    #[implicit(1)]
    pub register_num: Option<u64>,
    #[implicit(2)]
    pub register_digests: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
}

#[derive(asn1::Asn1Read)]
pub struct TcbInfo<'a> {
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
    pub operational_flags_mask: Option<asn1::BitString<'a>>,
    #[implicit(11)]
    pub integrity_registers: Option<asn1::SequenceOf<'a, IntegrityRegister<'a>>>,
}

#[derive(asn1::Asn1Read)]
pub struct Ueid<'a> {
    pub ueid: &'a [u8],
}
use std::fmt::Write as FmtWrite;
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
const TCG_DICE_KP_ATTEST_LOC_OID: &str = "2.23.133.5.4.100.9";
const TCG_DICE_KP_ECA_OID: &str = "2.23.133.5.4.100.12";

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
    pub vendor_info: Option<Vec<u8>>,
    pub tci_type: Option<Vec<u8>>,
    pub operational_flags_mask: Option<String>,
    pub integrity_registers: Vec<ParsedIntegrityRegister>,
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
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub signature_algorithm: String,
    pub not_before: String,
    pub not_after: String,
    pub public_key_info: String,
    pub profile: String,
    pub ueid: Option<Vec<u8>>,
    pub tcb_infos: Vec<ParsedTcbInfo>,
    pub extensions: Vec<ParsedExtension>,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02X}", b);
    }
    s
}

fn format_tci_type(bytes: &[u8]) -> String {
    let hex = hex_encode(bytes);
    if !bytes.is_empty() && bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        if let Ok(s) = std::str::from_utf8(bytes) {
            return format!("0x{} ('{}')", hex, s);
        }
    }
    format!("0x{}", hex)
}

fn format_bytes_brief(bytes: &[u8], max_len: usize) -> String {
    let hex = hex_encode(bytes);
    if hex.len() > max_len {
        format!("{}...", &hex[..max_len])
    } else {
        hex
    }
}

fn oid_friendly_name(oid_str: &str) -> String {
    match oid_str {
        "2.16.840.1.101.3.4.2.1" => "SHA-256 (2.16.840.1.101.3.4.2.1)".to_string(),
        "2.16.840.1.101.3.4.2.2" => "SHA-384 (2.16.840.1.101.3.4.2.2)".to_string(),
        "2.16.840.1.101.3.4.2.3" => "SHA-512 (2.16.840.1.101.3.4.2.3)".to_string(),
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87 (2.16.840.1.101.3.4.3.19)".to_string(),
        "1.2.840.10045.2.1" => "ecPublicKey".to_string(),
        "1.2.840.10045.3.1.7" => "secp256r1 (P-256)".to_string(),
        "1.3.132.0.34" => "secp384r1 (P-384)".to_string(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".to_string(),
        TCG_DICE_TCB_INFO_OID => "tcg-dice-TcbInfo".to_string(),
        TCG_DICE_MULTI_TCB_INFO_OID => "tcg-dice-MultiTcbInfo".to_string(),
        TCG_DICE_UEID_OID => "tcg-dice-Ueid".to_string(),
        TCG_DICE_KP_ATTEST_LOC_OID => "tcg-dice-kp-attestLoc".to_string(),
        TCG_DICE_KP_ECA_OID => "tcg-dice-kp-eca".to_string(),
        "2.5.29.19" => "basicConstraints".to_string(),
        "2.5.29.15" => "keyUsage".to_string(),
        "2.5.29.37" => "extendedKeyUsage".to_string(),
        "2.5.29.14" => "subjectKeyIdentifier".to_string(),
        "2.5.29.35" => "authorityKeyIdentifier".to_string(),
        "2.5.29.17" => "subjectAltName".to_string(),
        _ => oid_str.to_string(),
    }
}

fn parse_single_tcb_info(tcb: &TcbInfo) -> ParsedTcbInfo {
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
        flags: tcb.flags.clone().map(|b| format!("{:?}", b)),
        vendor_info: tcb.vendor_info.map(|v| v.to_vec()),
        tci_type: tcb.tci_type.map(|t| t.to_vec()),
        operational_flags_mask: tcb
            .operational_flags_mask
            .clone()
            .map(|b| format!("{:?}", b)),
        integrity_registers: parsed_irs,
    }
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
        flags: tcb.flags.clone().map(|b| format!("{:?}", b)),
        vendor_info: tcb.vendor_info.map(|v| v.to_vec()),
        tci_type: tcb.tci_type.map(|t| t.to_vec()),
        operational_flags_mask: None,
        integrity_registers: parsed_irs,
    }
}

fn parse_extensions<'a>(
    exts: impl Iterator<Item = &'a x509_parser::extensions::X509Extension<'a>>,
) -> (Vec<ParsedTcbInfo>, Option<Vec<u8>>, Vec<ParsedExtension>) {
    let mut tcb_infos = Vec::new();
    let mut ueid = None;
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
                });

            match parsed_seq {
                Ok(items) => {
                    let count = items.len();
                    tcb_infos.extend(items);
                    details = format!("Contains {} TCB Context(s)", count);
                }
                Err(e) => {
                    details = format!("Failed to parse SequenceOf<TcbInfo>: {:?}", e);
                }
            }
        } else if oid_str == TCG_DICE_UEID_OID {
            if let Ok(u) = asn1::parse_single::<Ueid>(ext.value) {
                ueid = Some(u.ueid.to_vec());
                details = format!("UEID: {}", hex_encode(u.ueid));
            } else {
                details = format!("Raw bytes: {}", hex_encode(ext.value));
            }
        } else {
            details = match ext.parsed_extension() {
                X509ParsedExtension::BasicConstraints(bc) => {
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
                    format!("SKI: {}", hex_encode(ski.0))
                }
                X509ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    let mut s = String::new();
                    if let Some(key_id) = &aki.key_identifier {
                        write!(s, "KeyID: {}", hex_encode(key_id.0)).unwrap();
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

    (tcb_infos, ueid, extensions)
}

fn infer_dpe_profile(pk_oid: &str, sig_alg_oid: &str, tcb_infos: &[ParsedTcbInfo]) -> String {
    if pk_oid == "2.16.840.1.101.3.4.3.19" || sig_alg_oid == "2.16.840.1.101.3.4.3.19" {
        return "ML-DSA-87 (PQC)".to_string();
    }

    let fwid_hash_oid = tcb_infos
        .first()
        .and_then(|tcb| tcb.fwids.first())
        .map(|fwid| fwid.hash_alg.as_str());

    if sig_alg_oid == "1.2.840.10045.4.3.3"
        || pk_oid == "1.3.132.0.34"
        || fwid_hash_oid == Some("2.16.840.1.101.3.4.2.2")
    {
        return "P384-SHA384".to_string();
    }

    if sig_alg_oid == "1.2.840.10045.4.3.2"
        || pk_oid == "1.2.840.10045.3.1.7"
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
    let serial = hex_encode(&tbs.serial.to_bytes_be());
    let sig_alg_oid = cert.signature_algorithm.algorithm.to_id_string();
    let pk_oid = tbs.subject_pki.algorithm.algorithm.to_id_string();

    let not_before = tbs.validity.not_before.to_string();
    let not_after = tbs.validity.not_after.to_string();

    let public_key_info = format!("{} ({})", pk_oid, oid_friendly_name(&pk_oid));

    let (tcb_infos, ueid, extensions) = parse_extensions(tbs.extensions().iter());

    let profile = infer_dpe_profile(&pk_oid, &sig_alg_oid, &tcb_infos);

    Ok(ParsedCert {
        is_csr: false,
        subject,
        issuer,
        serial,
        signature_algorithm: oid_friendly_name(&sig_alg_oid),
        not_before,
        not_after,
        public_key_info,
        profile,
        ueid,
        tcb_infos,
        extensions,
    })
}

fn parse_csr(csr: &X509CertificationRequest) -> Result<ParsedCert> {
    let cri = &csr.certification_request_info;

    let subject = cri.subject.to_string();
    let issuer = "N/A (CSR)".to_string();
    let serial = "N/A (CSR)".to_string();
    let sig_alg_oid = csr.signature_algorithm.algorithm.to_id_string();
    let pk_oid = cri.subject_pki.algorithm.algorithm.to_id_string();

    let not_before = "N/A (CSR)".to_string();
    let not_after = "N/A (CSR)".to_string();

    let public_key_info = format!("{} ({})", pk_oid, oid_friendly_name(&pk_oid));

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

    let (tcb_infos, ueid, extensions) = parse_extensions(csr_exts);

    let profile = infer_dpe_profile(&pk_oid, &sig_alg_oid, &tcb_infos);

    Ok(ParsedCert {
        is_csr: true,
        subject,
        issuer,
        serial,
        signature_algorithm: oid_friendly_name(&sig_alg_oid),
        not_before,
        not_after,
        public_key_info,
        profile,
        ueid,
        tcb_infos,
        extensions,
    })
}

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::Decode;

fn unwrap_raw_bytes(mut bytes: &[u8]) -> Vec<u8> {
    // 1. DPE Response Header ("REPD" magic = 0x52, 0x45, 0x50, 0x44)
    if bytes.len() >= 128 && &bytes[..4] == b"REPD" {
        bytes = &bytes[128..];
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

pub fn parse_cert_bytes(bytes: &[u8]) -> Result<ParsedCert> {
    let raw_der = if bytes.starts_with(b"-----BEGIN") {
        let p = ::pem::parse(bytes).context("Failed to parse PEM input")?;
        p.contents().to_vec()
    } else {
        bytes.to_vec()
    };

    let raw_der = unwrap_raw_bytes(&raw_der);

    if let Ok((_, cert)) = X509Certificate::from_der(&raw_der) {
        return parse_x509_cert(&cert);
    }

    if let Ok((_, csr)) = X509CertificationRequest::from_der(&raw_der) {
        return parse_csr(&csr);
    }

    Err(anyhow!(
        "Input could not be parsed as an X.509 Certificate or Certificate Signing Request (CSR)"
    ))
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
        let title = if is_root {
            format!("TCB Context {} (Root/Initial)", i)
        } else {
            format!("TCB Context {}", i)
        };

        let tci_type = tcb
            .tci_type
            .as_deref()
            .map(format_tci_type)
            .unwrap_or_else(|| "N/A".to_string());

        let svn = tcb
            .svn
            .map(|s| s.to_string())
            .unwrap_or_else(|| "N/A".to_string());

        let digest = if let Some(fwid) = tcb.fwids.first() {
            format_bytes_brief(&fwid.digest, 16)
        } else {
            "N/A".to_string()
        };

        let class = if is_root {
            ":::rootStyle"
        } else {
            ":::derivedStyle"
        };

        writeln!(
            out,
            "        NODE{}[\"<b>{}</b><br/>Type: <code>{}</code><br/>SVN: {}<br/>Digest: <code>{}</code>\"]{}",
            i, title, tci_type, svn, digest, class
        )
        .unwrap();

        if i > 0 {
            writeln!(out, "        NODE{} --> NODE{}", i - 1, i).unwrap();
        }
    }

    let cert_title = if cert.tcb_infos.is_empty() {
        if cert.is_csr {
            "Certificate Signing Request (CSR - 0 TCB Contexts)".to_string()
        } else {
            "Identity / CA Certificate (0 TCB Contexts)".to_string()
        }
    } else if cert.is_csr {
        "Certificate Signing Request (CSR)".to_string()
    } else {
        "Alias Certificate".to_string()
    };

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

pub fn generate_markdown(cert: &ParsedCert) -> String {
    let mut out = String::new();

    let doc_title = if cert.is_csr {
        "# DPE Certificate Signing Request (CSR) TCB Context Analysis"
    } else {
        "# DPE Certificate TCB Context Analysis"
    };

    writeln!(out, "{}\n", doc_title).unwrap();
    writeln!(out, "## Certificate Overview\n").unwrap();
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
        writeln!(out, "| **UEID** | `{}` |", hex_encode(ueid_bytes)).unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "## TCB Context Graph\n").unwrap();
    let mermaid = generate_mermaid_graph(cert);
    writeln!(out, "{}\n", mermaid).unwrap();

    if !cert.tcb_infos.is_empty() {
        writeln!(out, "## TCB Contexts Breakdown\n").unwrap();
        for (i, tcb) in cert.tcb_infos.iter().enumerate() {
            let title = if i == 0 {
                format!("### TCB Context {} (Root/Initial)\n", i)
            } else {
                format!("### TCB Context {}\n", i)
            };
            writeln!(out, "{}", title).unwrap();
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
                tcb.svn.map_or("N/A".to_string(), |s| s.to_string())
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
                writeln!(out, "| **Vendor Info** | `{}` |", hex_encode(vi)).unwrap();
            }
            if let Some(flags) = &tcb.flags {
                writeln!(out, "| **Flags** | `{}` |", flags).unwrap();
            }
            if let Some(op_flags) = &tcb.operational_flags_mask {
                writeln!(out, "| **Operational Flags Mask** | `{}` |", op_flags).unwrap();
            }
            writeln!(out).unwrap();

            if !tcb.fwids.is_empty() {
                writeln!(out, "#### FWIDs / Measurements").unwrap();
                writeln!(out).unwrap();
                for fwid in &tcb.fwids {
                    let alg_name = oid_friendly_name(&fwid.hash_alg);
                    writeln!(out, "- **Algorithm**: {}", alg_name).unwrap();
                    writeln!(out, "  - **Digest**: `{}`", hex_encode(&fwid.digest)).unwrap();
                }
                writeln!(out).unwrap();
            }

            if !tcb.integrity_registers.is_empty() {
                writeln!(out, "#### Integrity Registers").unwrap();
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
                            hex_encode(&fwid.digest)
                        )
                        .unwrap();
                    }
                }
                writeln!(out).unwrap();
            }
        }
    }

    let ext_title = if cert.is_csr {
        "## Requested Extensions"
    } else {
        "## X.509 Certificate Extensions"
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

    out
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn render_dpe_cert_markdown(cert_input: &[u8]) -> Result<String, JsValue> {
    let parsed =
        parse_cert_bytes(cert_input).map_err(|e| JsValue::from_str(&format!("{:#}", e)))?;
    Ok(generate_markdown(&parsed))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn get_default_sample_pem() -> String {
    DEFAULT_SAMPLE_PEM.to_string()
}
