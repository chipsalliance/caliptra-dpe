// Licensed under the Apache-2.0 license

#![no_std]

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
    #[implicit(6)]
    pub fwids: Option<asn1::SequenceOfWriter<'a, FwidWriter<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Ueid<'a> {
    pub ueid: &'a [u8],
}
