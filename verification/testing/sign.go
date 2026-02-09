// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// TestAsymmetricSigning obtains and validates signature of asymmetric signing.
// Check whether the digital signature returned by Sign command can be verified
// using public key in signing key certificate returned by CertifyKey command.
func TestAsymmetricSigning(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	useSimulation := false
	handle := getInitialContextHandle(d, c, t, useSimulation)
	// Get digest size
	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()
	tbsLen := profile.GetSignDataSize()

	// Validate asymmetric signature generated
	flags := client.SignFlags(0)

	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i)
	}

	tbs := make([]byte, tbsLen)
	for i := range tbs {
		tbs[i] = byte(i)
	}

	signResp, err := c.Sign(handle, seqLabel, flags, tbs)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing %v", err)
	}

	// Get signing key certificate using CertifyKey command
	certifiedKey, err := c.CertifyKey(handle, seqLabel, client.CertifyKeyX509, client.CertifyKeyFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not CertifyKey: %v", err)
	}

	if profile == client.ProfileMldsa87 {
		if len(signResp.Signature) != mldsa87.SignatureSize {
			t.Errorf("Incorrect signature length for ML-DSA-87: got %d, want %d", len(signResp.Signature), mldsa87.SignatureSize)
		}

		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(certifiedKey.Pub.X); err != nil {
			t.Fatalf("Failed to parse ML-DSA public key: %v", err)
		}

		if !mldsa87.Verify(&pk, tbs, nil, signResp.Signature) {
			t.Error("ML-DSA Signature Verification failed")
		}
		return
	}

	// Check certificate structure
	if _, err := x509.ParseCertificate(certifiedKey.Certificate); err != nil {
		t.Fatalf("[FATAL]: Could not parse certificate using crypto/x509: %v", err)
	}

	// Read public key
	var ec elliptic.Curve
	x := new(big.Int).SetBytes(certifiedKey.Pub.X)
	y := new(big.Int).SetBytes(certifiedKey.Pub.Y)

	if digestLen == 32 {
		ec = elliptic.P256()
	} else if digestLen == 48 {
		ec = elliptic.P384()
	}

	publicKey := ecdsa.PublicKey{Curve: ec, X: x, Y: y}

	// Build Signature from bytes
	r := new(big.Int).SetBytes(signResp.SignatureR)
	s := new(big.Int).SetBytes(signResp.SignatureS)

	// Verify Signature
	valid := ecdsa.Verify(&publicKey, tbs, r, s)
	if !valid {
		t.Error("Signature Verification failed")
	}
}

// TestSignSimulation checks command fails in simulated context because this context does not allow signing.
// This is because simulation context does not allow using context's private key.
func TestSignSimulation(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	useSimulation := true
	handle := getInitialContextHandle(d, c, t, useSimulation)
	defer func() {
		c.DestroyContext(handle)
	}()

	// Get digest size
	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()
	tbsLen := profile.GetSignDataSize()

	if _, err := c.Sign(handle, make([]byte, digestLen), client.SignFlags(0), make([]byte, tbsLen)); err == nil {
		t.Fatalf("[FATAL]: Should return %q, but returned no error", client.StatusInvalidArgument)
	} else if !errors.Is(err, client.StatusInvalidArgument) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", client.StatusInvalidArgument, err)
	}
}
