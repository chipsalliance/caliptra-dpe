use crate::{response::DpeErrorCode, x509::X509Error};
use core::mem::MaybeUninit;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer,
};

pub struct RawGeneralizedTimeRef<'a> {
    time: &'a [u8],
}

impl<'a> RawGeneralizedTimeRef<'a> {
    /// Length of an RFC 5280-flavored ASN.1 DER-encoded [`GeneralizedTime`].
    const LENGTH: u16 = 15;

    pub fn new(bytes: &'a [u8]) -> Result<Self, DpeErrorCode> {
        if bytes.len() != Self::LENGTH.into() {
            return Err(DpeErrorCode::InternalError);
        }

        Ok(Self { time: bytes })
    }
}

impl EncodeValue for RawGeneralizedTimeRef<'_> {
    fn value_len(&self) -> Result<Length, der::Error> {
        Ok(Self::LENGTH.into())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(self.time)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for RawGeneralizedTimeRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        let time = reader.read_slice(Self::LENGTH.into())?;
        Ok(Self { time })
    }
}

impl FixedTag for RawGeneralizedTimeRef<'_> {
    const TAG: Tag = Tag::GeneralizedTime;
}

// Wraps any asn1 encodable/decodable type and encodes/decodes it as an octet
// sring
pub struct OctetStringContainer<T>(pub T);

impl<'a, T> EncodeValue for OctetStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    fn value_len(&self) -> Result<Length, der::Error> {
        self.0.encoded_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        self.0.encode(writer)
    }
}

impl<'a, T> DecodeValue<'a> for OctetStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        Ok(OctetStringContainer::<T>(T::decode(reader)?))
    }
}

impl<'a, T> FixedTag for OctetStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    const TAG: Tag = Tag::OctetString;
}

// Wraps any asn1 encodable/decodable type and encodes/decodes it as an octet
// sring
pub struct BitStringContainer<T>(pub T);

impl<'a, T> EncodeValue for BitStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    fn value_len(&self) -> Result<Length, der::Error> {
        // Add 1 for unused bits
        Ok(self.0.encoded_len()?.saturating_add(Length::ONE))
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        // Write unused bits
        writer.write_byte(0u8)?;
        self.0.encode(writer)
    }
}

impl<'a, T> DecodeValue<'a> for BitStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        // Unused bits must be 0 for BitStringContainers. Skip unused bits byte.
        reader.read_byte()?;
        Ok(BitStringContainer::<T>(T::decode(reader)?))
    }
}

impl<'a, T> FixedTag for BitStringContainer<T>
where
    T: der::Encode + der::Decode<'a>,
{
    const TAG: Tag = Tag::BitString;
}

/// FixedSetOf provides a smaller SET OF implementation than der::SetOf
/// It assumes the caller has already ensured the set items are ordered properly
/// which removes the need to sort the items in the set.
///
/// DPE certificates generally only have one or two items in SetOf collections,
/// so keeping them manually sorted is trivial.
///
/// At the time of this writing, this removes ~8KiB from the X.509
/// implementation.
pub struct FixedSetOf<T, const N: usize> {
    values: [T; N],
}

impl<T, const N: usize> FixedSetOf<T, N> {
    pub fn new(values: [T; N]) -> Self {
        Self { values }
    }
}

impl<'a, T, const N: usize> DecodeValue<'a> for FixedSetOf<T, N>
where
    T: Decode<'a>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, der::Error> {
        reader.read_nested(header.length, |reader| {
            // SAFETY: This function fails if the ull array is not populated
            unsafe {
                let mut result = Self::new(MaybeUninit::uninit().assume_init());

                for i in 0..N {
                    result.values[i] = T::decode(reader)?;
                }

                Ok(result)
            }
        })
    }
}

impl<'a, T, const N: usize> EncodeValue for FixedSetOf<T, N>
where
    T: 'a + Decode<'a> + Encode,
{
    fn value_len(&self) -> Result<Length, der::Error> {
        let mut len = Length::ZERO;
        for elem in self.values.iter() {
            len = (len + elem.encoded_len()?)?;
        }

        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        for elem in self.values.iter() {
            elem.encode(writer)?;
        }

        Ok(())
    }
}

impl<'a, T, const N: usize> FixedTag for FixedSetOf<T, N>
where
    T: Decode<'a>,
{
    const TAG: Tag = Tag::Set;
}

pub struct RawDerSequenceRef<'a> {
    val: &'a [u8],
}

impl<'a> RawDerSequenceRef<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, DpeErrorCode> {
        // Skip header
        let mut reader = der::SliceReader::new(data)
            .map_err(|_| DpeErrorCode::from(X509Error::InvalidRawDer))?;
        let header = Header::decode(&mut reader)
            .map_err(|_| DpeErrorCode::from(X509Error::InvalidRawDer))?;
        let len: u32 = header.length.into();
        let offset: u32 = reader.position().into();

        Ok(Self {
            val: &data[offset as usize..(offset + len) as usize],
        })
    }
}

impl<'a> EncodeValue for RawDerSequenceRef<'a> {
    fn value_len(&self) -> Result<Length, der::Error> {
        self.val.len().try_into()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(self.val)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for RawDerSequenceRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, der::Error> {
        let val = reader.read_slice(header.length)?;
        Ok(Self { val })
    }
}

impl<'a> FixedTag for RawDerSequenceRef<'a> {
    const TAG: Tag = Tag::Sequence;
}

// Saves a few-hundred bytes over using der crate PrintableStringRef
pub struct UncheckedPrintableStringRef<'a> {
    s: &'a [u8],
}

impl<'a> UncheckedPrintableStringRef<'a> {
    pub fn new(s: &'a [u8]) -> Self {
        Self { s }
    }
}

impl<'a> EncodeValue for UncheckedPrintableStringRef<'a> {
    fn value_len(&self) -> Result<Length, der::Error> {
        // PANIC FREE: Values guaranteed to be less than u16 max
        Ok(self.s.len().try_into().unwrap())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(self.s)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for UncheckedPrintableStringRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, der::Error> {
        let s = reader.read_slice(header.length)?;
        Ok(Self { s })
    }
}

impl<'a> FixedTag for UncheckedPrintableStringRef<'a> {
    const TAG: Tag = Tag::PrintableString;
}

pub struct U32OctetString(pub u32);

impl U32OctetString {
    const LENGTH: u16 = 4;
}

impl FixedTag for U32OctetString {
    const TAG: Tag = Tag::OctetString;
}

impl EncodeValue for U32OctetString {
    fn value_len(&self) -> Result<Length, der::Error> {
        Ok(Self::LENGTH.into())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(&self.0.to_be_bytes())?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for U32OctetString {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        let val = reader.read_slice(Self::LENGTH.try_into()?)?;
        // PANIC FREE: val is guaranteed to be 4 bytes
        Ok(Self(u32::from_be_bytes(val.try_into().unwrap())))
    }
}

pub struct OidRef<'a>(&'a [u8]);

impl<'a> OidRef<'a> {
    pub fn new(oid: &'a [u8]) -> Self {
        Self(oid)
    }
}

impl EncodeValue for OidRef<'_> {
    fn value_len(&self) -> Result<Length, der::Error> {
        self.0.len().try_into()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(self.0)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for OidRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, der::Error> {
        let val = reader.read_slice(header.length)?;
        Ok(Self(val))
    }
}

impl FixedTag for OidRef<'_> {
    const TAG: Tag = Tag::ObjectIdentifier;
}

pub struct FixedOctetStringRef<'a, const SIZE: u16>(&'a [u8]);

impl<'a, const SIZE: u16> FixedOctetStringRef<'a, SIZE> {
    pub fn new(data: &'a [u8]) -> Result<Self, DpeErrorCode> {
        if data.len() != SIZE.into() {
            return Err(DpeErrorCode::from(X509Error::InvalidRawDer))
        }

        Ok(Self(data))
    }
}

impl<const SIZE: u16> FixedTag for FixedOctetStringRef<'_, SIZE> {
    const TAG: Tag = Tag::OctetString;
}

impl<'a, const SIZE: u16> EncodeValue for FixedOctetStringRef<'a, SIZE> {
    fn value_len(&self) -> Result<Length, der::Error> {
        Ok(SIZE.into())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), der::Error> {
        writer.write(self.0)?;
        Ok(())
    }
}

impl<'a, const SIZE: u16> DecodeValue<'a> for  FixedOctetStringRef<'a, SIZE>{
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self, der::Error> {
        Ok(Self(reader.read_slice(SIZE.try_into()?)?))
    }
}
