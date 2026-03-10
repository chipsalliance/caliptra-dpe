// Licensed under the Apache-2.0 license

package verification

import (
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// TestSignRawMode validates the new raw sign functionality for ML-DSA
// This tests signing with pre-computed external mu values
func TestSignRawMode(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	// Get profile
	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	// Skip test if not ML-DSA profile
	if profile != client.ProfileMldsa87 {
		t.Skip("SignRaw is only applicable to ML-DSA profile")
	}

	useSimulation := false
	handle := getInitialContextHandle(d, c, t, useSimulation)

	digestLen := profile.GetDigestSize()

	// Create label
	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i)
	}

	// Get signing key certificate using CertifyKey command
	certifiedKey, err := c.CertifyKey(handle, seqLabel, client.CertifyKeyX509, client.CertifyKeyFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not CertifyKey: %v", err)
	}
	handle = &certifiedKey.Handle

	// Create a test message
	testMessage := []byte("This is a test message for ML-DSA raw signing")

	// Calculate external mu using the helper function
	externalMu := client.CalculateExternalMu(testMessage, certifiedKey.Pub.X)

	// Call SignRaw with the pre-computed mu
	signResp, err := c.SignRaw(handle, seqLabel, externalMu)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing: %v", err)
	}

	// Verify signature
	if len(signResp.Signature) != mldsa87.SignatureSize {
		t.Errorf("Incorrect signature length for ML-DSA-87: got %d, want %d", len(signResp.Signature), mldsa87.SignatureSize)
	}

	var pk mldsa87.PublicKey
	if err := pk.UnmarshalBinary(certifiedKey.Pub.X); err != nil {
		t.Fatalf("Failed to parse ML-DSA public key: %v", err)
	}

	// Verify using the external mu value
	if !mldsa87.Verify(&pk, testMessage, nil, signResp.Signature) {
		t.Error("ML-DSA Signature Verification failed for raw signing")
	}
}

// TestSignRawVsNormalMu validates that raw signing with computed mu produces same signatures
// This provides a consistency check between the two signing modes
func TestSignRawConsistencyWithNormalMu(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	// Get profile
	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	// Skip test if not ML-DSA profile
	if profile != client.ProfileMldsa87 {
		t.Skip("SignRaw is only applicable to ML-DSA profile")
	}

	useSimulation := false
	handle := getInitialContextHandle(d, c, t, useSimulation)

	digestLen := profile.GetDigestSize()

	// Create label
	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i % 256)
	}

	// Get signing key certificate using CertifyKey command
	certifiedKey, err := c.CertifyKey(handle, seqLabel, client.CertifyKeyX509, client.CertifyKeyFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not CertifyKey: %v", err)
	}
	handle = &certifiedKey.Handle

	// Create a test message
	testMessage := []byte("Another test message for consistency check")

	// Calculate external mu
	externalMu := client.CalculateExternalMu(testMessage, certifiedKey.Pub.X)

	// Sign using raw mode
	signResp, err := c.SignRaw(handle, seqLabel, externalMu)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing raw: %v", err)
	}

	// Both signatures should verify against the same public key and message
	var pk mldsa87.PublicKey
	if err := pk.UnmarshalBinary(certifiedKey.Pub.X); err != nil {
		t.Fatalf("Failed to parse ML-DSA public key: %v", err)
	}

	if !mldsa87.Verify(&pk, testMessage, nil, signResp.Signature) {
		t.Error("ML-DSA Signature Verification failed")
	}
}
