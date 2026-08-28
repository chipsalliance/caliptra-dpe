// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/mldsa"
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

// TestSignRawMode validates the new raw sign functionality for ML-DSA
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

	// Call SignRaw with the message itself (DPE should handle hashing / mu calculation).
	signResp, err := c.SignRaw(handle, seqLabel, testMessage)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing: %v", err)
	}

	// Verify signature
	if len(signResp.Signature) != mldsa.MLDSA87SignatureSize {
		t.Errorf("Incorrect signature length for ML-DSA-87: got %d, want %d", len(signResp.Signature), mldsa.MLDSA87SignatureSize)
	}

	pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), certifiedKey.Pub.X)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA public key: %v", err)
	}

	// Verify using the original message
	if err := mldsa.Verify(pk, testMessage, signResp.Signature, nil); err != nil {
		t.Errorf("ML-DSA Signature Verification failed for raw signing: %v", err)
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

	// Sign using raw mode (message is passed directly)
	rawSignResp, err := c.SignRaw(handle, seqLabel, testMessage)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing raw: %v", err)
	}

	// Sign using the normal Sign API (providing the externally computed mu)
	externalMu := client.CalculateExternalMu(testMessage, certifiedKey.Pub.X)
	normalSignResp, err := c.Sign(handle, seqLabel, 0, externalMu)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing normally: %v", err)
	}

	// Both signatures should match and verify against the same public key and message
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), certifiedKey.Pub.X)
	if err != nil {
		t.Fatalf("Failed to parse ML-DSA public key: %v", err)
	}

	if err := mldsa.Verify(pk, testMessage, rawSignResp.Signature, nil); err != nil {
		t.Errorf("ML-DSA Signature Verification failed for SignRaw: %v", err)
	}

	if err := mldsa.Verify(pk, testMessage, normalSignResp.Signature, nil); err != nil {
		t.Errorf("ML-DSA Signature Verification failed for Sign with external mu: %v", err)
	}

	if !bytes.Equal(rawSignResp.Signature, normalSignResp.Signature) {
		t.Error("Raw and normal signatures do not match")
	}
}
