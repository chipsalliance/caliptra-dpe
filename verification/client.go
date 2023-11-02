// Licensed under the Apache-2.0 license

package verification

import (
	"fmt"
)

const (
	MaxChunkSize = 2048
)

// Transport is an interface to define how to test and send messages to a DPE instance.
type Transport interface {
	// Send a command to the DPE instance.
	SendCmd(buf []byte) ([]byte, error)
}

// TODO: Include curve
type DPEPubKey struct {
	X []byte
	Y []byte
}

type CertifiedKey struct {
	Handle      ContextHandle
	Pub         DPEPubKey
	Certificate []byte
}

type DPETCI struct {
	CumulativeTCI []byte
	CurrentTCI    []byte
}

type DPESignedHash struct {
	Handle           ContextHandle
	HmacOrSignatureR []byte
	SignatureS       []byte
}

type DPEClient interface {
	InitializeContext(flags InitCtxFlags) (*ContextHandle, error)
	GetProfile() (*GetProfileResp, error)
	DeriveChild(handle *ContextHandle, inputData []byte, flags DeriveChildFlags, tciType uint32, targetLocality uint32) (*DeriveChildResp, error)
	CertifyKey(handle *ContextHandle, label []byte, format CertifyKeyFormat, flags CertifyKeyFlags) (*CertifiedKey, error)
	GetCertificateChain() ([]byte, error)
	TagTCI(handle *ContextHandle, tag TCITag) (*ContextHandle, error)
	GetTaggedTCI(tag TCITag) (*DPETCI, error)
	DestroyContext(handle *ContextHandle, flags DestroyCtxFlags) error
	RotateContextHandle(handle *ContextHandle, flags RotateContextHandleFlags) (*ContextHandle, error)
	Sign(handle *ContextHandle, label []byte, flags SignFlags, toBeSigned []byte) (*DPESignedHash, error)
}

func NewClient(t Transport, p Profile) (DPEClient, error) {
	switch p {
	case ProfileP256SHA256:
		return NewDPEABI256(t)
	case ProfileP384SHA384:
		return NewDPEABI384(t)
	default:
		return nil, fmt.Errorf("Cannot create a DPE client for profile %d", p)
	}
}
