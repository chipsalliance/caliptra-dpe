// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/ecdsa"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

// TestAsymmetricSignWithExported obtains and validates signature of asymmetric signing.
// Check whether the digital signature returned by Sign command can be verified
// using public key in signing key certificate returned by CertifyKey command.
func TestAsymmetricSignWithExported(d client.TestDPEInstance, c client.DPEClient, t *testing.T) {
	useSimulation := false
	handle := getInitialContextHandle(d, c, t, useSimulation)
	profile, err := client.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()
	resp, err := c.DeriveContext(handle, make([]byte, digestLen), client.DeriveContextFlags(client.CdiExport|client.CreateCertificate), 0, 0)
	if err != nil {
		t.Errorf("[ERROR]: Error while creating child context handle: %s", err)
	}

	// Validate asymmetric signature generated
	flags := client.SignWithExportedFlags(0)

	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i)
	}

	tbs := make([]byte, digestLen)
	for i := range tbs {
		tbs[i] = byte(i)
	}

	signResp, err := c.SignWithExported(flags, tbs, resp.ExportedCdi)
	if err != nil {
		t.Fatalf("[FATAL]: Error while signing %v", err)
	}

	// Check certificate structure
	certificate, err := x509.ParseCertificate(resp.NewCertificate)
	if err != nil {
		t.Fatalf("[FATAL]: Could not parse certificate using crypto/x509: %v", err)
	}

	// Build Signature from bytes
	r := new(big.Int).SetBytes(signResp.SignatureR)
	s := new(big.Int).SetBytes(signResp.SignatureS)

	pubKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("[FATAL]: Could not cast certificate public key to ecdsa.PublicKey")
	}

	// Verify Signature
	valid := ecdsa.Verify(pubKey, tbs, r, s)
	if !valid {
		t.Error("Signature Verification failed")
	}
}
