// Licensed under the Apache-2.0 license

package client

import (
	"fmt"
	"reflect"
)

// Profile represents a supported algorithm profile (i.e., hash algorithm and ECC curve).
type Profile uint32

const (
	// ProfileP256SHA256 is NIST P-256, SHA-256
	ProfileP256SHA256 Profile = 1
	// ProfileP384SHA384 is NIST P-384, SHA-384
	ProfileP384SHA384 Profile = 2
)

// GetDigestSize gets the digest size of the profile's supported hash algorithm
func (p Profile) GetDigestSize() int {
	switch p {
	case ProfileP256SHA256:
		return 32
	case ProfileP384SHA384:
		return 48
	}
	return 0
}

// GetECCIntSize gets the ECC int size of the profile's supported ECC curve
func (p Profile) GetECCIntSize() int {
	switch p {
	case ProfileP256SHA256:
		return 32
	case ProfileP384SHA384:
		return 48
	}
	return 0
}

func (p Profile) String() string {
	switch p {
	case ProfileP256SHA256:
		return "DPE_PROFILE_IROT_P256_SHA256"
	case ProfileP384SHA384:
		return "DPE_PROFILE_IROT_P384_SHA384"
	}
	return fmt.Sprintf("unrecognized DPE profile: 0x%0x", uint32(p))
}

// Curve is a type constraint enumerating the supported ECC curves for DPE profiles.
type Curve interface {
	NISTP256Parameter | NISTP384Parameter

	Bytes() []byte
}

func CurveIntLen[C Curve]() int {
	return reflect.TypeOf((*C)(nil)).Elem().Len()
}

// NISTP256Parameter represents a NIST P-256 curve parameter, i.e., an x, y, r, or s value.
type NISTP256Parameter [32]byte

// Bytes returns a big-endian byte slice of a P256 int
func (p NISTP256Parameter) Bytes() []byte {
	return p[:]
}

// NISTP384Parameter represents a NIST P-384 curve parameter, i.e., an x, y, r, or s value.
type NISTP384Parameter [48]byte

// Bytes returns a big-endian byte slice of a P384 int
func (p NISTP384Parameter) Bytes() []byte {
	return p[:]
}

// DigestAlgorithm is a type constraint enumerating the supported hashing algorithms for DPE profiles.
type DigestAlgorithm interface {
	SHA256Digest | SHA384Digest

	Bytes() []byte
}

func NewDigest[D DigestAlgorithm](b []byte) (D, error) {
	var d D
	switch tmp := any(&d).(type) {
	case *SHA256Digest:
		copy(tmp[:], b[:])
	case *SHA384Digest:
		copy(tmp[:], b[:])
	default:
		return d, fmt.Errorf("Invalid digest type %v", reflect.TypeOf(tmp))
	}

	return d, nil
}

func DigestLen[D DigestAlgorithm]() int {
	return reflect.TypeOf((*D)(nil)).Elem().Len()
}

// SHA256Digest represents a SHA-256 digest value.
type SHA256Digest [32]byte

// Bytes returns a byte slice of the SHA256 digest
func (d SHA256Digest) Bytes() []byte {
	return d[:]
}

// SHA384Digest represents a SHA-384 digest value.
type SHA384Digest [48]byte

// Bytes returns a byte slice of the SHA384 digest
func (d SHA384Digest) Bytes() []byte {
	return d[:]
}
