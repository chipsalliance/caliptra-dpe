// Licensed under the Apache-2.0 license

/// An OID in the two representations used by the golden generators and tests.
/// `der_content` excludes the OBJECT IDENTIFIER tag and length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Oid {
    pub dotted: &'static str,
    pub der_content: &'static [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionDefinition {
    pub oid: Oid,
    pub critical: bool,
}

pub const UEID_OID: Oid = Oid {
    dotted: "2.23.133.5.4.4",
    der_content: &[0x67, 0x81, 0x05, 0x05, 0x04, 0x04],
};

pub const MULTI_TCB_INFO_OID: Oid = Oid {
    dotted: "2.23.133.5.4.5",
    der_content: &[0x67, 0x81, 0x05, 0x05, 0x04, 0x05],
};

pub const ATTEST_LOC_OID: Oid = Oid {
    dotted: "2.23.133.5.4.100.9",
    der_content: &[0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x09],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoldenProfile {
    P256,
    P384,
    Mldsa87,
}

impl core::str::FromStr for GoldenProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "p256" => Ok(Self::P256),
            "p384" => Ok(Self::P384),
            "mldsa87" => Ok(Self::Mldsa87),
            _ => Err("expected one of: p256, p384, mldsa87"),
        }
    }
}

impl GoldenProfile {
    pub const ALL: [Self; 3] = [Self::P256, Self::P384, Self::Mldsa87];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoldenKeyAlgorithm {
    Ecdsa { curve_oid: Oid, scalar_size: usize },
    Mldsa87 { seed_size: usize },
}

/// Semantic inputs shared by the independently generated golden artifacts,
/// their parser smoke tests, and the DPE encoder comparison tests.
///
/// OpenSSL command-line spellings intentionally do not live here. Consumers
/// translate these values into the representation required by their encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoldenDefinitions {
    pub profile: GoldenProfile,
    pub artifact_suffix: &'static str,
    pub hash_size: usize,
    pub hash_oid: Oid,
    pub key_algorithm: GoldenKeyAlgorithm,
    pub deterministic_key_fill: u8,

    pub certificate_version: u8,
    pub csr_version: u8,
    pub subject_common_name: &'static str,
    pub csr_subject_serial: &'static str,
    pub certificate_serial: &'static str,
    pub not_before: &'static str,
    pub not_after: &'static str,

    pub is_ca: bool,
    pub basic_constraints_critical: bool,
    pub key_usage_critical: bool,
    pub digital_signature: bool,
    pub key_cert_sign: bool,
    pub extended_key_usage: ExtensionDefinition,
    pub include_subject_key_identifier: bool,
    pub include_authority_key_identifier: bool,

    pub ueid: ExtensionDefinition,
    pub ueid_fill: u8,
    pub multi_tcb_info: ExtensionDefinition,
    pub tcb_info_count: usize,
    pub fwids_per_tcb_info: usize,
    pub fwid_digest_fill: u8,
    pub svn: u32,
    pub locality: u32,
    pub tci_type: u32,
    pub supports_recursive: bool,
}

impl GoldenDefinitions {
    const fn build(profile: GoldenProfile) -> Self {
        let (artifact_suffix, hash_size, hash_oid, key_algorithm) = match profile {
            GoldenProfile::P256 => (
                "p256",
                32,
                Oid {
                    dotted: "2.16.840.1.101.3.4.2.1",
                    der_content: &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                },
                GoldenKeyAlgorithm::Ecdsa {
                    curve_oid: Oid {
                        dotted: "1.2.840.10045.3.1.7",
                        der_content: &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
                    },
                    scalar_size: 32,
                },
            ),
            GoldenProfile::P384 => (
                "p384",
                48,
                Oid {
                    dotted: "2.16.840.1.101.3.4.2.2",
                    der_content: &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
                },
                GoldenKeyAlgorithm::Ecdsa {
                    curve_oid: Oid {
                        dotted: "1.3.132.0.34",
                        der_content: &[0x2b, 0x81, 0x04, 0x00, 0x22],
                    },
                    scalar_size: 48,
                },
            ),
            GoldenProfile::Mldsa87 => (
                "mldsa87",
                48,
                Oid {
                    dotted: "2.16.840.1.101.3.4.2.2",
                    der_content: &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
                },
                GoldenKeyAlgorithm::Mldsa87 { seed_size: 32 },
            ),
        };

        Self {
            profile,
            artifact_suffix,
            hash_size,
            hash_oid,
            key_algorithm,
            deterministic_key_fill: 0x11,
            certificate_version: 2,
            csr_version: 0,
            subject_common_name: "DPE Leaf",
            csr_subject_serial: "0000",
            certificate_serial: "0",
            // Use GeneralizedTime on both the OpenSSL and custom encoder paths.
            not_before: "20500227000000Z",
            not_after: "99991231235959Z",
            is_ca: false,
            basic_constraints_critical: true,
            key_usage_critical: true,
            digital_signature: true,
            key_cert_sign: false,
            extended_key_usage: ExtensionDefinition {
                oid: ATTEST_LOC_OID,
                critical: true,
            },
            include_subject_key_identifier: false,
            include_authority_key_identifier: true,
            ueid: ExtensionDefinition {
                oid: UEID_OID,
                critical: true,
            },
            ueid_fill: 0,
            multi_tcb_info: ExtensionDefinition {
                oid: MULTI_TCB_INFO_OID,
                critical: true,
            },
            tcb_info_count: 1,
            fwids_per_tcb_info: 1,
            fwid_digest_fill: 0,
            svn: 0,
            locality: 0,
            tci_type: 0,
            supports_recursive: false,
        }
    }
}

impl From<GoldenProfile> for GoldenDefinitions {
    fn from(profile: GoldenProfile) -> Self {
        Self::build(profile)
    }
}

#[derive(asn1::Asn1Read)]
pub struct Fwid<'a> {
    pub hash_alg: asn1::ObjectIdentifier,
    pub digest: &'a [u8],
}

#[derive(asn1::Asn1Write)]
pub struct FwidWriter<'a> {
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

/// Minimal TcbInfo representation used to independently generate golden data.
#[derive(asn1::Asn1Write)]
pub struct TcbInfoWriter<'a> {
    #[implicit(3)]
    pub svn: Option<u64>,
    #[implicit(6)]
    pub fwids: Option<asn1::SequenceOfWriter<'a, FwidWriter<'a>>>,
    #[implicit(8)]
    pub vendor_info: Option<&'a [u8]>,
    #[implicit(9)]
    pub tci_type: Option<&'a [u8]>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Ueid<'a> {
    pub ueid: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_representations_match() {
        for oid in [UEID_OID, MULTI_TCB_INFO_OID, ATTEST_LOC_OID] {
            let parsed = asn1::ObjectIdentifier::from_string(oid.dotted).unwrap();
            let der = asn1::write_single(&parsed).unwrap();
            assert_eq!(der[0], 0x06);
            assert_eq!(der[1] as usize, oid.der_content.len());
            assert_eq!(&der[2..], oid.der_content);
        }
    }

    #[test]
    fn profiles_parse_and_convert_to_definitions() {
        for (name, profile, hash_size) in [
            ("p256", GoldenProfile::P256, 32),
            ("p384", GoldenProfile::P384, 48),
            ("mldsa87", GoldenProfile::Mldsa87, 48),
        ] {
            assert_eq!(name.parse::<GoldenProfile>().unwrap(), profile);
            let definitions: GoldenDefinitions = profile.into();
            assert_eq!(definitions.profile, profile);
            assert_eq!(definitions.artifact_suffix, name);
            assert_eq!(definitions.hash_size, hash_size);
        }
    }
}
