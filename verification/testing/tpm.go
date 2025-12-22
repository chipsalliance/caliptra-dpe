// Licensed under the Apache-2.0 license

package verification

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math"
	"math/big"
	"testing"

	dpe "github.com/chipsalliance/caliptra-dpe/verification/client"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}
)

func flushAllContexts(t *testing.T, tpm io.ReadWriteCloser) {
	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(tpm, handleType)
		if err != nil {
			t.Fatalf("[FATAL]: Error getting handles %s", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(tpm, handle); err != nil {
				t.Fatalf("[FATAL]: Error flushing handle 0x%x: %v", handle, err)
			}
			totalHandles++
		}
	}
}

func startTpmSession(t *testing.T, tpm io.ReadWriteCloser, alg tpm2.Algorithm) (tpmutil.Handle, []byte, error) {

	flushAllContexts(t, tpm)
	sessHandle, nonce, err := tpm2.StartAuthSession(tpm,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		alg)

	if err != nil {
		t.Fatalf("[FATAL]: StartAuthSession() failed: %v", err)
	}

	return sessHandle, nonce, nil
}

// TestTpmPolicySigning tests using DPE to satisfy TPM PolicySigned
func TestTpmPolicySigning(d dpe.TestDPEInstance, c dpe.DPEClient, t *testing.T) {
	simulation := false
	ctx := getInitialContextHandle(d, c, t, simulation)
	var ec tpm2.EllipticCurve
	var alg tpm2.Algorithm

	profile, err := dpe.GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	if profile == dpe.ProfileMldsa87ExternalMu {
		// TODO(clundin): Add Test support for ML-DSA.
		t.Skip("TPM Policy Signing test not supported for ML-DSA")
	}
	digestLen := profile.GetDigestSize()

	if digestLen == len(dpe.SHA256Digest{0}) {
		alg = tpm2.AlgSHA256
		ec = tpm2.CurveNISTP256
	} else if digestLen == len(dpe.SHA384Digest{0}) {
		alg = tpm2.AlgSHA384
		ec = tpm2.CurveNISTP384
	}

	// Create tpm auth session to get nonce and form label which is digest
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatalf("[FATAL]: Can't open TPM")
	}

	sessHandle, nonce, err := startTpmSession(t, tpm, alg)
	if err != nil {
		t.Fatalf("[FATAL]: Error in getting TPM nonce")
	}

	defer func() {
		if err := tpm.Close(); err != nil {
			t.Fatalf("[FATAL]: Can't close TPM %s", err)
		}
	}()

	defer tpm2.FlushContext(tpm, sessHandle)

	// Build SignHash request
	expiry := int32(math.MinInt32)
	digest := getDigest(nonce, expiry, digestLen)

	seqLabel := make([]byte, digestLen)
	for i := range seqLabel {
		seqLabel[i] = byte(i)
	}

	// Get signed hash from DPE
	signResp, err := c.Sign(ctx, seqLabel, dpe.SignFlags(0), digest)
	if err != nil {
		t.Fatalf("[FATAL]: Could not sign: %v", err)
	}

	certifyKeyResp, err := c.CertifyKey(&(signResp.Handle), seqLabel, dpe.CertifyKeyX509, dpe.CertifyKeyFlags(0))
	if err != nil {
		t.Fatalf("[FATAL]: Could not CertifyKey: %v", err)
	}

	pubKey := extractPubKey(t, certifyKeyResp.Certificate)

	// Get TPM handle loaded with public key
	pkh := loadPubKey(t, pubKey, tpm, alg, ec)

	// Get encoded signature from TPM
	r := new(big.Int).SetBytes(signResp.SignatureR)
	s := new(big.Int).SetBytes(signResp.SignatureS)

	encodedSignature := getEncodedSignature(t, r, s, alg)

	// Verify Policy with Signature
	_, tkt, err := tpm2.PolicySigned(tpm, pkh, sessHandle, nonce, nil, nil, expiry, encodedSignature)
	if err != nil {
		t.Fatalf("[FATAL]: PolicySigning failed: %v", err)
	}

	if tkt != nil {
		t.Log("Policy signing succeeded.")
	} else {
		t.Fatal("Policy signing failed, unable to receive signed ticket associated with policy")
	}
}

func getDigest(nonce []byte, expiry int32, digestLen int) []byte {

	expBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expBytes, uint32(expiry))

	toDigest := append(nonce, expBytes...)

	digest := make([]byte, digestLen)
	if digestLen == len(dpe.SHA256Digest{0}) {
		hash := sha256.Sum256(toDigest)
		digest = hash[:]
	} else if digestLen == len(dpe.SHA384Digest{0}) {
		hash := sha512.Sum384(toDigest)
		digest = hash[:]
	}
	return digest
}

func extractPubKey(t *testing.T, leafBytes []byte) *ecdsa.PublicKey {
	var x509Cert *x509.Certificate
	var err error

	// Check whether certificate is DER encoded.
	if x509Cert, err = x509.ParseCertificate(leafBytes); err != nil {
		t.Fatalf("[FATAL]: Could not parse certificate using crypto/x509: %v", err)
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
	if err != nil {
		t.Fatalf("[FATAL]: Could not marshal pub key: %v", err)
	}

	// Parse the DER-encoded public key
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyDer)
	if err != nil {
		t.Fatalf("[FATAL]: Failed to parse DER-encoded public key: %v", err)
	}

	if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
		t.Fatal("[FATAL]: Public key is not a ecdsa key")
	}

	return pubKey.(*ecdsa.PublicKey)
}

func loadPubKey(t *testing.T, pubKey any, tpm io.ReadWriteCloser, alg tpm2.Algorithm, ec tpm2.EllipticCurve) tpmutil.Handle {
	var tpmPublic tpm2.Public

	// Create a tpm2.Public structure from the parsed ECDSA public key
	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		byteSize := pubKey.Params().BitSize / 8
		x := make([]byte, byteSize)
		y := make([]byte, byteSize)
		x = pubKey.X.FillBytes(x)
		y = pubKey.Y.FillBytes(y)
		tpmPublic = tpm2.Public{
			Type:       tpm2.AlgECC, // ECDSA key type
			NameAlg:    alg,
			Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
			ECCParameters: &tpm2.ECCParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgECDSA,
					Hash: alg,
				},
				CurveID: ec,
				Point: tpm2.ECPoint{
					XRaw: x,
					YRaw: y,
				},
			},
		}
	default:
		t.Fatalf("[FATAL]: Unsupported public key type")
	}

	pkh, _, err := tpm2.LoadExternal(tpm, tpmPublic, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		t.Fatalf("[FATAL]: Unable to load external public key. Error: %v", err)
	}

	return pkh
}

func getEncodedSignature(t *testing.T, r *big.Int, s *big.Int, alg tpm2.Algorithm) []byte {
	signature := tpm2.Signature{
		Alg: tpm2.AlgECDSA,
		ECC: &tpm2.SignatureECC{
			HashAlg: alg,
			R:       r,
			S:       s,
		},
	}
	encodedSign, err := signature.Encode()
	if err != nil {
		t.Fatalf("[FATAL]: Unable to encode signature: %v", err)
	}
	return encodedSign
}
