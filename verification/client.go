// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"fmt"
)

const (
	MaxChunkSize = 2048
)

type Support struct {
	Simulation    bool
	ExtendTci     bool
	AutoInit      bool
	Tagging       bool
	RotateContext bool
	X509          bool
	Csr           bool
	IsSymmetric   bool
	InternalInfo  bool
	InternalDice  bool
	IsCA          bool
}

// Transport is an interface to define how to test and send messages to a DPE instance.
type Transport interface {
	// Send a command to the DPE instance.
	SendCmd(buf []byte) ([]byte, error)
}

type Client interface {
	GetProfile() (*GetProfileResp, error)
	InitializeContext(cmd *InitCtxCmd) (*InitCtxResp, error)
	DestroyContext(cmd *DestroyCtxCmd) error
	CertifyKey(cmd *CertifyKeyReq) (*CertifyKeyResp, error)
	GetCertificateChain() (*GetCertificateChainResp, error)
	TagTCI(cmd *TagTCIReq) (*TagTCIResp, error)
	GetTaggedTCI(cmd *GetTaggedTCIReq) (*GetTaggedTCIResp, error)
}

// ClientImpl is a connection to a DPE instance, parameterized by hash algorithm and ECC curve.
type ClientImpl[CurveParameter Curve, Digest DigestAlgorithm] struct {
	transport    Transport
	Profile      Profile
	MajorVersion uint16
	MinorVersion uint16
	VendorId     uint32
	VendorSku    uint32
	MaxTciNodes  uint32
	Flags        uint32
}

// Client256 is a client that implements DPE_PROFILE_IROT_P256_SHA256
type Client256 = ClientImpl[NISTP256Parameter, SHA256Digest]

// Client384 is a client that implements DPE_PROFILE_IROT_P384_SHA384
type Client384 = ClientImpl[NISTP384Parameter, SHA384Digest]

// dpeProfileImplementsTypeConstraints checks that the requested ClientImpl type constraints are compatible with the DPE profile.
func dpeProfileImplementsTypeConstraints[C Curve, D DigestAlgorithm](profile Profile) error {
	// Test that the expected value types produced by each DPE profile can be assigned to variables of type C and D
	var c C
	var d D
	switch profile {
	case ProfileP256SHA256:
		// We must cast c and d to any in order to perform type assertions on them.
		// https://go.googlesource.com/proposal/+/refs/heads/master/design/43651-type-parameters.md#why-not-permit-type-assertions-on-values-whose-type-is-a-type-parameter
		if _, ok := any(c).(NISTP256Parameter); !ok {
			return fmt.Errorf("an incorrect ECC parameter type was passed to a DPE implementing DPE_PROFILE_IROT_P256_SHA256")
		}
		if _, ok := any(d).(SHA256Digest); !ok {
			return fmt.Errorf("an incorrect digest type was passed to a DPE implementing DPE_PROFILE_IROT_P256_SHA256")
		}
		return nil
	case ProfileP384SHA384:
		if _, ok := any(c).(NISTP384Parameter); !ok {
			return fmt.Errorf("an incorrect ECC parameter type was passed to a DPE implementing DPE_PROFILE_IROT_P384_SHA384")
		}
		if _, ok := any(d).(SHA384Digest); !ok {
			return fmt.Errorf("an incorrect digest type was passed to a DPE implementing DPE_PROFILE_IROT_P384_SHA384")
		}
		return nil
	}
	return fmt.Errorf("unsupported DPE profile: %v", profile)
}

func NewClient(t Transport) (Client, error) {
	rsp, err := getProfile(t)
	if err != nil {
		return nil, fmt.Errorf("could not query DPE for profile: %w", err)
	}

	switch rsp.Profile {
	case ProfileP256SHA256:
		return newClient256(t)
	case ProfileP384SHA384:
		return newClient384(t)
	}

	return nil, fmt.Errorf("Could not create client for profile %v", rsp.Profile)
}

// NewClientImpl initializes a new DPE client.
func newClientImpl[C Curve, D DigestAlgorithm](t Transport) (*ClientImpl[C, D], error) {
	rsp, err := getProfile(t)
	if err != nil {
		return nil, fmt.Errorf("could not query DPE for profile: %w", err)
	}

	if err := dpeProfileImplementsTypeConstraints[C, D](rsp.Profile); err != nil {
		return nil, err
	}

	return &ClientImpl[C, D]{
		transport:    t,
		Profile:      rsp.Profile,
		MajorVersion: rsp.MajorVersion,
		MinorVersion: rsp.MinorVersion,
		VendorId:     rsp.VendorId,
		VendorSku:    rsp.VendorSku,
		Flags:        rsp.Flags,
	}, nil
}

// NewClient256 is a convenience wrapper for NewClient[NISTP256Parameter, SHA256Digest].
func newClient256(t Transport) (*ClientImpl[NISTP256Parameter, SHA256Digest], error) {
	return newClientImpl[NISTP256Parameter, SHA256Digest](t)
}

// NewClient256 is a convenience wrapper for NewClient[NISTP384Parameter, SHA384Digest].
func newClient384(t Transport) (*ClientImpl[NISTP384Parameter, SHA384Digest], error) {
	return newClientImpl[NISTP384Parameter, SHA384Digest](t)
}

func (c *ClientImpl[_, _]) InitializeContext(cmd *InitCtxCmd) (*InitCtxResp, error) {
	var respStruct InitCtxResp

	if _, err := execCommand(c.transport, CommandInitializeContext, c.Profile, cmd, &respStruct); err != nil {
		return nil, err
	}

	return &respStruct, nil
}

// getProfile is an internal helper for handling GetProfile as part of either the client API or initialization.
func getProfile(t Transport) (*GetProfileResp, error) {
	// GetProfile does not take any parameters.
	cmd := struct{}{}

	// Define an anonymous struct for the actual wire-format members of GetProfile,
	// since GetProfileResp includes the actual profile copied from the response header.
	respStruct := struct {
		MajorVersion uint16
		MinorVersion uint16
		VendorId     uint32
		VendorSku    uint32
		MaxTciNodes  uint32
		Flags        uint32
	}{}

	respHdr, err := execCommand(t, CommandGetProfile, 0, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &GetProfileResp{
		// Special case for GetProfile: copy the profile from the inner packet header into the response structure.
		Profile:      respHdr.Profile,
		MajorVersion: respStruct.MajorVersion,
		MinorVersion: respStruct.MinorVersion,
		VendorId:     respStruct.VendorId,
		VendorSku:    respStruct.VendorSku,
		MaxTciNodes:  respStruct.MaxTciNodes,
		Flags:        respStruct.Flags,
	}, nil
}

func (c *ClientImpl[_, _]) GetProfile() (*GetProfileResp, error) {
	return getProfile(c.transport)
}

// Send the command to destroy a context.
func (c *ClientImpl[_, _]) DestroyContext(cmd *DestroyCtxCmd) error {
	// DestroyContext does not return any parameters.
	respStruct := struct{}{}

	if _, err := execCommand(c.transport, CommandDestroyContext, c.Profile, cmd, &respStruct); err != nil {
		return err
	}

	return nil
}

// CertifyKey calls the DPE CertifyKey command.
func (c *ClientImpl[CurveParameter, Digest]) CertifyKey(cmd *CertifyKeyReq) (*CertifyKeyResp, error) {
	// Define an anonymous struct for the response, because we have to accept the variable-sized certificate.
	reqStruct := struct {
		ContextHandle ContextHandle
		Flags         CertifyKeyFlags
		Label         Digest
		Format        CertifyKeyFormat
	}{}
	respStruct := struct {
		NewContextHandle  [16]byte
		DerivedPublicKeyX CurveParameter
		DerivedPublicKeyY CurveParameter
		CertificateSize   uint32
		Certificate       [2048]byte
	}{}

	reqStruct.ContextHandle = cmd.ContextHandle
	reqStruct.Flags = cmd.Flags
	reqStruct.Label = Digest(cmd.Label)
	reqStruct.Format = cmd.Format

	_, err := execCommand(c.transport, CommandCertifyKey, c.Profile, &reqStruct, &respStruct)
	if err != nil {
		return nil, err
	}

	// Check that the reported cert size makes sense.
	if respStruct.CertificateSize > 2048 {
		return nil, fmt.Errorf("DPE reported a %d-byte cert, which was larger than 2048", respStruct.CertificateSize)
	}

	return &CertifyKeyResp{
		NewContextHandle:  respStruct.NewContextHandle,
		DerivedPublicKeyX: respStruct.DerivedPublicKeyX.Slice(),
		DerivedPublicKeyY: respStruct.DerivedPublicKeyY.Slice(),
		Certificate:       respStruct.Certificate[:respStruct.CertificateSize],
	}, nil
}

// GetCertificateChain calls the DPE GetCertificateChain command.
func (c *ClientImpl[_, _]) GetCertificateChain() (*GetCertificateChainResp, error) {
	var certs GetCertificateChainResp

	// Initialize request input parameters
	cmd := GetCertificateChainReq{
		Offset: 0,
		Size:   MaxChunkSize,
	}

	for {
		respStruct := struct {
			CertificateSize  uint32
			CertificateChain [2048]byte
		}{}

		_, err := execCommand(c.transport, CommandGetCertificateChain, c.Profile, cmd, &respStruct)
		if err == StatusInvalidArgument {
			// This indicates that there are no more bytes to be read in certificate chain
			break
		} else if err != nil {
			// This indicates error in processing GetCertificateChain command
			return nil, err
		}

		certs.CertificateChain = append(certs.CertificateChain, respStruct.CertificateChain[:respStruct.CertificateSize]...)
		if MaxChunkSize > respStruct.CertificateSize {
			break
		}
		// Increment offset in steps of 2048 bytes till end of cert chain
		cmd.Offset += MaxChunkSize
	}

	if len(certs.CertificateChain) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	return &certs, nil
}

// TagTCI calls the DPE TagTCI command.
func (c *ClientImpl[_, _]) TagTCI(cmd *TagTCIReq) (*TagTCIResp, error) {
	var respStruct TagTCIResp

	_, err := execCommand(c.transport, CommandTagTCI, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, nil
}

// GetTaggedTCI calls the DPE GetTaggedTCI command.
func (c *ClientImpl[_, Digest]) GetTaggedTCI(cmd *GetTaggedTCIReq) (*GetTaggedTCIResp, error) {
	respStruct := struct {
		CumulativeTCI Digest
		CurrentTCI    Digest
	}{}

	_, err := execCommand(c.transport, CommandGetTaggedTCI, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &GetTaggedTCIResp{
		CumulativeTCI: respStruct.CumulativeTCI.Slice(),
		CurrentTCI:    respStruct.CurrentTCI.Slice(),
	}, nil
}

func (s *Support) ToFlags() uint32 {
	flags := uint32(0)
	if s.Simulation {
		flags |= (1 << 31)
	}
	if s.ExtendTci {
		flags |= (1 << 30)
	}
	if s.AutoInit {
		flags |= (1 << 29)
	}
	if s.Tagging {
		flags |= (1 << 28)
	}
	if s.RotateContext {
		flags |= (1 << 27)
	}
	if s.X509 {
		flags |= (1 << 26)
	}
	if s.Csr {
		flags |= (1 << 25)
	}
	if s.IsSymmetric {
		flags |= (1 << 24)
	}
	if s.InternalInfo {
		flags |= (1 << 23)
	}
	if s.InternalDice {
		flags |= (1 << 22)
	}
	if s.IsCA {
		flags |= (1 << 21)
	}
	return flags
}
