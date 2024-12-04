// Licensed under the Apache-2.0 license

// Package client provides a modular DPE client that can be used to
// communicate with DPE over different transports.
package client

import (
	"fmt"
)

const (
	// MaxChunkSize is the max size of a DPE certificate chunk
	MaxChunkSize = 2048
)

// Transport is an interface to define how to test and send messages to a DPE instance.
type Transport interface {
	// Send a command to the DPE instance.
	SendCmd(buf []byte) ([]byte, error)
}

// DPEPubKey is an ECC public point
// TODO: Include curve
type DPEPubKey struct {
	X []byte
	Y []byte
}

// CertifiedKey is a response from DPE CertifyKey
type CertifiedKey struct {
	Handle      ContextHandle
	Pub         DPEPubKey
	Certificate []byte
}

// DPETCI holds the current and cumulative measurements for a DPE TCI node
type DPETCI struct {
	CumulativeTCI []byte
	CurrentTCI    []byte
}

// DPESignedHash is the response from DPE Sign
type DPESignedHash struct {
	Handle           ContextHandle
	HmacOrSignatureR []byte
	SignatureS       []byte
}

// DPEClient is a generic interface to a DPE instance
type DPEClient interface {
	InitializeContext(flags InitCtxFlags) (*ContextHandle, error)
	GetProfile() (*GetProfileResp, error)
	CertifyKey(handle *ContextHandle, label []byte, format CertifyKeyFormat, flags CertifyKeyFlags) (*CertifiedKey, error)
	GetCertificateChain() ([]byte, error)
	DestroyContext(handle *ContextHandle) error
	DeriveContext(handle *ContextHandle, inputData []byte, flags DeriveContextFlags, tciType uint32, targetLocality uint32) (*DeriveContextResp, error)
	RotateContextHandle(handle *ContextHandle, flags RotateContextHandleFlags) (*ContextHandle, error)
	Sign(handle *ContextHandle, label []byte, flags SignFlags, toBeSigned []byte) (*DPESignedHash, error)
}

// NewClient returns a new DPE client
func NewClient(t Transport, p Profile) (DPEClient, error) {
	switch p {
	case ProfileMinP256SHA256:
		return NewDPEABI256Min(t)
	case ProfileMinP384SHA384:
		return NewDPEABI384Min(t)
	case ProfileP256SHA256:
		return NewDPEABI256(t)
	case ProfileP384SHA384:
		return NewDPEABI384(t)
	default:
		return nil, fmt.Errorf("cannot create a DPE client for profile %d", p)
	}
}
