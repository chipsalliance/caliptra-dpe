// Licensed under the Apache-2.0 license

package verification

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

// TestAsymmetricSigning obtains and validates signature of asymmetric signing.
// Check whether the digital signature returned by Sign command can be verified
// using public key in signing key certificate returned by CertifyKey command.
// Inspite of the DPE profile supporting symmetric key, for symmetric signing it must be enabled
// explicitly in Sign command flags. Else asymmetric signing is used as default.
func TestAsymmetricSigning(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	useSimulation := false
	handle := getInitialContextHandle(d, c, t, useSimulation)
	// Get digest size
	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()

	// Validate asymmetric signature generated
	flags := client.SignFlags(0)

	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i)
	}

	tbs := make([]byte, digestLen)
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
	r := new(big.Int).SetBytes(signResp.HmacOrSignatureR)
	s := new(big.Int).SetBytes(signResp.SignatureS)

	// Verify Signature
	valid := ecdsa.Verify(&publicKey, tbs, r, s)
	if !valid {
		t.Error("Signature Verification failed")
	}
}

// TestSignSimulation cheks command fails in simulated context because this context does not allow signing.
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

	if _, err := c.Sign(handle, make([]byte, digestLen), client.SignFlags(client.IsSymmetric), make([]byte, digestLen)); err == nil {
		t.Fatalf("[FATAL]: Should return %q, but returned no error", client.StatusInvalidArgument)
	} else if !errors.Is(err, client.StatusInvalidArgument) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", client.StatusInvalidArgument, err)
	}

	if _, err := c.Sign(handle, make([]byte, digestLen), client.SignFlags(0), make([]byte, digestLen)); err == nil {
		t.Fatalf("[FATAL]: Should return %q, but returned no error", client.StatusInvalidArgument)
	} else if !errors.Is(err, client.StatusInvalidArgument) {
		t.Fatalf("[FATAL]: Incorrect error type. Should return %q, but returned %q", client.StatusInvalidArgument, err)
	}
}

// TestSymmetricSigning obtains HMAC (symmetric signature) generated and compares for varying label inputs.
// Signature created is deterministic and depends on label passed to command.
// This is because label is used by DPE in symmetric key derivation.
// Invoking Sign command multiple times with same label and same content (TBS) should return same signature
// but it should return different signatures for different labels despite having the same content (To Be Signed content).
func TestSymmetricSigning(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	useSimulation := false
	handle := getInitialContextHandle(d, c, t, useSimulation)

	// Get digest size
	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()
	label := make([]byte, digestLen)
	for i := range label {
		label[i] = byte(i)
	}

	tbs := make([]byte, digestLen)
	for i := range tbs {
		tbs[i] = byte(i)
	}

	signedData, err := c.Sign(handle, label, client.SignFlags(client.IsSymmetric), tbs)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing %v", err)
	}

	// Rerun with same label and compare signature emitted.
	signedDataWithSameLabel, err := c.Sign(handle, label, client.SignFlags(client.IsSymmetric), tbs)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing %v", err)
	}

	// Symmetric sign only populates HmacOrSignatureR. SignatureS is all zeroes.
	if !bytes.Equal(signedDataWithSameLabel.HmacOrSignatureR, signedData.HmacOrSignatureR) {
		t.Errorf("[ERROR]: Signature varies for same label, want %v but got %v", signedData.HmacOrSignatureR, signedDataWithSameLabel.HmacOrSignatureR)
	}

	// Rerun with different label, signature must change this time
	newLabel := make([]byte, digestLen)
	for i := range newLabel {
		newLabel[i] = byte(0)
	}

	signedDataWithDiffLabel, err := c.Sign(handle, newLabel, client.SignFlags(client.IsSymmetric), tbs)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing %v", err)
	}

	if bytes.Equal(signedDataWithDiffLabel.HmacOrSignatureR, signedData.HmacOrSignatureR) {
		t.Errorf("[ERROR]: Signature must vary for different label despite having same toBeSigned content, want new signature but got old %v", signedData.HmacOrSignatureR)
	}
}
