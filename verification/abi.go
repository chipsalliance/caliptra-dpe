// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"fmt"
	"reflect"
)

const (
	CmdMagic  uint32 = 0x44504543
	RespMagic uint32 = 0x44504552

	CURRENT_PROFILE_MAJOR_VERSION uint16 = 0
	CURRENT_PROFILE_MINOR_VERSION uint16 = 8
)

type CommandCode uint32

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

const (
	CommandGetProfile          CommandCode = 0x1
	CommandInitializeContext   CommandCode = 0x7
	CommandCertifyKey          CommandCode = 0x9
	CommandDestroyContext      CommandCode = 0xf
	CommandGetCertificateChain CommandCode = 0x80
	CommandExtendTci           CommandCode = 0x81
	CommandTagTCI              CommandCode = 0x82
	CommandGetTaggedTCI        CommandCode = 0x83
)

type CommandHdr struct {
	magic   uint32
	cmd     CommandCode
	profile Profile
}

type RespHdr struct {
	Magic   uint32
	Status  Status
	Profile Profile
}

type InitCtxCmd struct {
	flags InitCtxFlags
}

type InitCtxFlags uint32

const (
	InitIsSimulation InitCtxFlags = 1 << 31
	InitIsDefault    InitCtxFlags = 1 << 30
)

type ContextHandle [16]byte

type DestroyCtxCmd struct {
	handle ContextHandle
}

type InitCtxResp struct {
	Handle ContextHandle
}

type GetProfileResp struct {
	Profile      Profile
	MajorVersion uint16
	MinorVersion uint16
	VendorId     uint32
	VendorSku    uint32
	MaxTciNodes  uint32
	Flags        uint32
}

type CertifyKeyFlags uint32

const (
	CertifyAddIsCA CertifyKeyFlags = 1 << 30
)

type CertifyKeyFormat uint32

const (
	CertifyKeyX509 CertifyKeyFormat = 0
	CertifyKeyCsr  CertifyKeyFormat = 1
)

type CertifyKeyReq[Digest DigestAlgorithm] struct {
	ContextHandle ContextHandle
	Flags         CertifyKeyFlags
	Label         Digest
	Format        CertifyKeyFormat
}

type CertifyKeyResp[CurveParameter Curve, Digest DigestAlgorithm] struct {
	NewContextHandle  ContextHandle
	DerivedPublicKeyX CurveParameter
	DerivedPublicKeyY CurveParameter
	Certificate       []byte
}

type GetCertificateChainReq struct {
	Offset uint32
	Size   uint32
}
type GetCertificateChainResp struct {
	CertificateSize  uint32
	CertificateChain []byte
}

type ExtendTciCmd[Digest DigestAlgorithm] struct {
	Handle ContextHandle
	Data   Digest
}

type ExtendTciResp struct {
	NewContextHandle ContextHandle
}

type TCITag uint32

type TagTCIReq struct {
	ContextHandle ContextHandle
	Tag           TCITag
}

type TagTCIResp struct {
	NewContextHandle ContextHandle
}

type GetTaggedTCIReq struct {
	Tag TCITag
}

type GetTaggedTCIResp[Digest DigestAlgorithm] struct {
	CumulativeTCI Digest
	CurrentTCI    Digest
}

// dpeABI is a connection to a DPE instance, parameterized by hash algorithm and ECC curve.
type dpeABI[CurveParameter Curve, Digest DigestAlgorithm] struct {
	transport    Transport
	Profile      Profile
	MajorVersion uint16
	MinorVersion uint16
	VendorId     uint32
	VendorSku    uint32
	MaxTciNodes  uint32
	Flags        uint32
}

// DPEABI256 is a client that implements DPE_PROFILE_IROT_P256_SHA256
type DPEABI256 = dpeABI[NISTP256Parameter, SHA256Digest]

// DPEABI384 is a client that implements DPE_PROFILE_IROT_P384_SHA384
type DPEABI384 = dpeABI[NISTP384Parameter, SHA384Digest]

// dpeProfileImplementsTypeConstraints checks that the requested dpeABI type constraints are compatible with the DPE profile.
func dpeProfileImplementsTypeConstraints[C Curve, D DigestAlgorithm](profile Profile) error {
	// Test that the expected value types produced by each DPE profile can be assigned to variables of type C and D
	var c C
	var d D

	var targetProfile Profile
	_, isP256 := any(c).(NISTP256Parameter)
	_, isSHA256 := any(d).(SHA256Digest)
	_, isP384 := any(c).(NISTP384Parameter)
	_, isSHA384 := any(d).(SHA384Digest)

	if isP256 && isSHA256 {
		targetProfile = ProfileP256SHA256
	} else if isP384 && isSHA384 {
		targetProfile = ProfileP384SHA384
	} else {
		return fmt.Errorf("Client requested (Curve = %v, Digest = %v), this is an invalid DPE profile",
			reflect.TypeOf(c), reflect.TypeOf(d))
	}

	if profile != targetProfile {
		fmt.Errorf("Expected profile %v, got profile %v", targetProfile, profile)
	}

	return nil
}

// newDPEABI initializes a new DPE client.
func newDPEABI[C Curve, D DigestAlgorithm](t Transport) (*dpeABI[C, D], error) {
	rsp, err := getProfile(t)
	if err != nil {
		return nil, fmt.Errorf("could not query DPE for profile: %w", err)
	}

	if err := dpeProfileImplementsTypeConstraints[C, D](rsp.Profile); err != nil {
		return nil, err
	}

	return &dpeABI[C, D]{
		transport:    t,
		Profile:      rsp.Profile,
		MajorVersion: rsp.MajorVersion,
		MinorVersion: rsp.MinorVersion,
		VendorId:     rsp.VendorId,
		VendorSku:    rsp.VendorSku,
		Flags:        rsp.Flags,
	}, nil
}

// NewDPEABI256 is a convenience wrapper for NewDPEABI[NISTP256Parameter, SHA256Digest].
func NewDPEABI256(t Transport) (*dpeABI[NISTP256Parameter, SHA256Digest], error) {
	return newDPEABI[NISTP256Parameter, SHA256Digest](t)
}

// NewDPEABI256 is a convenience wrapper for NewDPEABI[NISTP384Parameter, SHA384Digest].
func NewDPEABI384(t Transport) (*dpeABI[NISTP384Parameter, SHA384Digest], error) {
	return newDPEABI[NISTP384Parameter, SHA384Digest](t)
}

func (c *dpeABI[_, _]) InitializeContextABI(cmd *InitCtxCmd) (*InitCtxResp, error) {
	var respStruct InitCtxResp

	if _, err := execCommand(c.transport, CommandInitializeContext, c.Profile, cmd, &respStruct); err != nil {
		return nil, err
	}

	return &respStruct, nil
}

func GetTransportProfile(t Transport) (Profile, error) {
	resp, err := getProfile(t)
	if err != nil {
		return 0, err
	}

	return resp.Profile, nil
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

func (c *dpeABI[_, _]) GetProfileABI() (*GetProfileResp, error) {
	return getProfile(c.transport)
}

// Send the command to destroy a context.
func (c *dpeABI[_, _]) DestroyContextABI(cmd *DestroyCtxCmd) error {
	// DestroyContext does not return any parameters.
	respStruct := struct{}{}

	if _, err := execCommand(c.transport, CommandDestroyContext, c.Profile, cmd, &respStruct); err != nil {
		return err
	}

	return nil
}

// CertifyKey calls the DPE CertifyKey command.
func (c *dpeABI[CurveParameter, Digest]) CertifyKeyABI(cmd *CertifyKeyReq[Digest]) (*CertifyKeyResp[CurveParameter, Digest], error) {
	// Define an anonymous struct for the response, because we have to accept the variable-sized certificate.
	respStruct := struct {
		NewContextHandle  [16]byte
		DerivedPublicKeyX CurveParameter
		DerivedPublicKeyY CurveParameter
		CertificateSize   uint32
		Certificate       [2048]byte
	}{}

	_, err := execCommand(c.transport, CommandCertifyKey, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	// Check that the reported cert size makes sense.
	if respStruct.CertificateSize > 2048 {
		return nil, fmt.Errorf("DPE reported a %d-byte cert, which was larger than 2048", respStruct.CertificateSize)
	}

	return &CertifyKeyResp[CurveParameter, Digest]{
		NewContextHandle:  respStruct.NewContextHandle,
		DerivedPublicKeyX: respStruct.DerivedPublicKeyX,
		DerivedPublicKeyY: respStruct.DerivedPublicKeyY,
		Certificate:       respStruct.Certificate[:respStruct.CertificateSize],
	}, nil
}

// ExtendTci calls the DPE ExtendTci command.
func (c *dpeABI[_, Digest]) ExtendTciABI(cmd *ExtendTciCmd[Digest]) (*ExtendTciResp, error) {
	var respStruct ExtendTciResp

	_, err := execCommand(c.transport, CommandExtendTci, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, nil
}

// GetCertificateChain calls the DPE GetCertificateChain command.
func (c *dpeABI[_, _]) GetCertificateChainABI() (*GetCertificateChainResp, error) {
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
func (c *dpeABI[_, _]) TagTCIABI(cmd *TagTCIReq) (*TagTCIResp, error) {
	var respStruct TagTCIResp

	_, err := execCommand(c.transport, CommandTagTCI, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, nil
}

// GetTaggedTCI calls the DPE GetTaggedTCI command.
func (c *dpeABI[_, Digest]) GetTaggedTCIABI(cmd *GetTaggedTCIReq) (*GetTaggedTCIResp[Digest], error) {
	var respStruct GetTaggedTCIResp[Digest]

	_, err := execCommand(c.transport, CommandGetTaggedTCI, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, nil
}

func (c *dpeABI[_, _]) InitializeContext(flags InitCtxFlags) (*ContextHandle, error) {
	cmd := InitCtxCmd{flags: flags}
	resp, err := c.InitializeContextABI(&cmd)
	if err != nil {
		return nil, err
	}

	return &resp.Handle, nil
}

func (c *dpeABI[_, _]) GetProfile() (*GetProfileResp, error) {
	return c.GetProfileABI()
}

func (c *dpeABI[_, Digest]) CertifyKey(handle *ContextHandle, label []byte, format CertifyKeyFormat, flags CertifyKeyFlags) (*CertifiedKey, error) {
	cmd := CertifyKeyReq[Digest]{
		ContextHandle: *handle,
		Flags:         flags,
		Label:         Digest(label),
		Format:        format,
	}

	if len(label) != len(cmd.Label) {
		return nil, fmt.Errorf("Invalid digest length")
	}

	resp, err := c.CertifyKeyABI(&cmd)
	if err != nil {
		return nil, err
	}

	key := &CertifiedKey{
		Handle: resp.NewContextHandle,
		Pub: DPEPubKey{
			X: resp.DerivedPublicKeyX.Bytes(),
			Y: resp.DerivedPublicKeyY.Bytes(),
		},
		Certificate: resp.Certificate,
	}

	return key, nil
}

func (c *dpeABI[_, _]) TagTCI(handle *ContextHandle, tag TCITag) (*ContextHandle, error) {
	cmd := TagTCIReq{
		ContextHandle: *handle,
		Tag:           tag,
	}

	resp, err := c.TagTCIABI(&cmd)
	if err != nil {
		return nil, err
	}

	return &resp.NewContextHandle, nil
}

func (c *dpeABI[_, _]) GetTaggedTCI(tag TCITag) (*DPETCI, error) {
	cmd := GetTaggedTCIReq{
		Tag: tag,
	}

	resp, err := c.GetTaggedTCIABI(&cmd)
	if err != nil {
		return nil, err
	}

	return &DPETCI{
		CumulativeTCI: resp.CumulativeTCI.Bytes(),
		CurrentTCI:    resp.CurrentTCI.Bytes(),
	}, nil
}

func (c *dpeABI[_, _]) DestroyContext(handle *ContextHandle) error {
	cmd := DestroyCtxCmd{
		handle: *handle,
	}

	return c.DestroyContextABI(&cmd)
}

func (c *dpeABI[_, Digest]) ExtendTci(Handle *ContextHandle, data []byte) (*ContextHandle, error) {
	cmd := ExtendTciCmd[Digest]{
		Handle: *Handle,
		Data:   Digest(data),
	}

	if len(data) != len(cmd.Data) {
		return nil, fmt.Errorf("Invalid digest length")
	}

	resp, err := c.ExtendTciABI(&cmd)
	if err != nil {
		return nil, err
	}

	return &resp.NewContextHandle, nil
}

func (c *dpeABI[_, _]) GetCertificateChain() ([]byte, error) {
	resp, err := c.GetCertificateChainABI()
	if err != nil {
		return nil, err
	}

	return resp.CertificateChain, nil
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
