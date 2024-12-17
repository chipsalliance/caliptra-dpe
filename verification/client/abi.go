// Licensed under the Apache-2.0 license

package client

import (
	"fmt"
	"reflect"
)

// DefaultContextHandle is the default DPE context handle
var DefaultContextHandle = ContextHandle{0}

// Profile-defined constants
const (
	CmdMagic  uint32 = 0x44504543
	RespMagic uint32 = 0x44504552

	CurrentProfileMajorVersion uint16 = 0
	CurrentProfileMinorVersion uint16 = 11
)

// CommandCode is a DPE command code
type CommandCode uint32

// Support is the set of features a DPE supports
type Support struct {
	Simulation          bool
	Recursive           bool
	AutoInit            bool
	RotateContext       bool
	X509                bool
	Csr                 bool
	IsSymmetric         bool
	InternalInfo        bool
	InternalDice        bool
	IsCA                bool
	RetainParentContext bool
	CdiExport           bool
}

// profileCommandCodes holds command codes for a specific revision of the
// DPE iRoT profile.
type profileCommandCodes struct {
	GetProfile          CommandCode
	InitializeContext   CommandCode
	DeriveContext       CommandCode
	CertifyKey          CommandCode
	Sign                CommandCode
	RotateContextHandle CommandCode
	DestroyContext      CommandCode
	GetCertificateChain CommandCode
}

// profileInfo holds constants defined in a specific version of the DPE iRoT
// profile.
type profileInfo struct {
	MajorVersion uint16
	MinorVersion uint16
	Codes        profileCommandCodes
}

// getProfileInfoV08 returns profile info for v0.8 of the DPE iRoT profile
func getProfileInfoV08() profileInfo {
	return profileInfo{
		Codes: profileCommandCodes{
			GetProfile:          0x1,
			InitializeContext:   0x5,
			DeriveContext:       0x6,
			CertifyKey:          0x7,
			Sign:                0x8,
			RotateContextHandle: 0xE,
			DestroyContext:      0xF,
			GetCertificateChain: 0x80,
		},
		MajorVersion: 0,
		MinorVersion: 8,
	}
}

// getProfileInfoV09 returns profile info for v0.9 of the DPE iRoT profile
func getProfileInfoV09() profileInfo {
	return profileInfo{
		Codes: profileCommandCodes{
			GetProfile:          0x1,
			InitializeContext:   0x7,
			DeriveContext:       0x8,
			CertifyKey:          0x9,
			Sign:                0xa,
			RotateContextHandle: 0xe,
			DestroyContext:      0xf,
			GetCertificateChain: 0x10,
		},
		MajorVersion: 0,
		MinorVersion: 9,
	}
}

// CommandHdr is the DPE command header common to all commands
type CommandHdr struct {
	magic   uint32
	cmd     CommandCode
	profile Profile
}

// RespHdr is the DPE response header common to all responses
type RespHdr struct {
	Magic   uint32
	Status  Status
	Profile Profile
}

// InitCtxCmd is the input parameters to InitializeContext
type InitCtxCmd struct {
	flags InitCtxFlags
}

// InitCtxFlags is the input flags to InitializeContext
type InitCtxFlags uint32

// Supported flags to InitializeContext
const (
	InitIsSimulation InitCtxFlags = 1 << 31
	InitIsDefault    InitCtxFlags = 1 << 30
)

// ContextHandle is a DPE context handle
type ContextHandle [16]byte

// ExportedCdi is a handle to an exported CDI
type ExportedCdi [32]byte

// DestroyCtxCmd is input parameters to DestroyContext
type DestroyCtxCmd struct {
	handle ContextHandle
}

// InitCtxResp is the response parameters from InitializeContext
type InitCtxResp struct {
	Handle ContextHandle
}

// GetProfileResp is the response from GetProfile
type GetProfileResp struct {
	Profile      Profile
	MajorVersion uint16
	MinorVersion uint16
	VendorID     uint32
	VendorSku    uint32
	MaxTciNodes  uint32
	Flags        uint32
}

// CertifyKeyFlags is the input flags to CertifyKey
type CertifyKeyFlags uint32

// CertifyKeyFormat is the requested output format of the DPE key certification
type CertifyKeyFormat uint32

// Supported CertifyKey formats
const (
	CertifyKeyX509 CertifyKeyFormat = 0
	CertifyKeyCsr  CertifyKeyFormat = 1
)

// CertifyKeyReq is the input request to CertifyKey
type CertifyKeyReq[Digest DigestAlgorithm] struct {
	ContextHandle ContextHandle
	Flags         CertifyKeyFlags
	Format        CertifyKeyFormat
	Label         Digest
}

// CertifyKeyResp is the output response from CertifyKey
type CertifyKeyResp[CurveParameter Curve, Digest DigestAlgorithm] struct {
	NewContextHandle  ContextHandle
	DerivedPublicKeyX CurveParameter
	DerivedPublicKeyY CurveParameter
	Certificate       []byte
}

// GetCertificateChainReq is the input request to GetCertificateChain
type GetCertificateChainReq struct {
	Offset uint32
	Size   uint32
}

// GetCertificateChainResp is the output response from GetCertificateChain
type GetCertificateChainResp struct {
	CertificateSize  uint32
	CertificateChain []byte
}

// RotateContextHandleFlags is the input flags to RotateContextHandle
type RotateContextHandleFlags uint32

// Supported RotateContextHandle flags
const (
	TargetIsDefault RotateContextHandleFlags = 1 << 31
)

// RotateContextHandleCmd is the input command to RotateContextHandle
type RotateContextHandleCmd struct {
	Handle ContextHandle
	Flags  RotateContextHandleFlags
}

// RotatedContextHandle is the response from RotateContextHandle
type RotatedContextHandle struct {
	NewContextHandle ContextHandle
}

// DeriveContextFlags is the input flags to DeriveContext
type DeriveContextFlags uint32

// Supported flags to DeriveContext
const (
	InternalInputInfo   DeriveContextFlags = 1 << 31
	InternalInputDice   DeriveContextFlags = 1 << 30
	RetainParentContext DeriveContextFlags = 1 << 29
	MakeDefault         DeriveContextFlags = 1 << 28
	ChangeLocality      DeriveContextFlags = 1 << 27
	InputAllowCA        DeriveContextFlags = 1 << 26
	InputAllowX509      DeriveContextFlags = 1 << 25
	Recursive           DeriveContextFlags = 1 << 24
	CdiExport           DeriveContextFlags = 1 << 23
	CreateCertificate   DeriveContextFlags = 1 << 22
)

// DeriveContextReq is the input request to DeriveContext
type DeriveContextReq[Digest DigestAlgorithm] struct {
	ContextHandle  ContextHandle
	InputData      Digest
	Flags          DeriveContextFlags
	TciType        uint32
	TargetLocality uint32
}

// DeriveContextResp is the output response from DeriveContext
type DeriveContextResp struct {
	NewContextHandle    ContextHandle
	ParentContextHandle ContextHandle
	ExportedCdi         ExportedCdi
	CertificateSize     uint32
	NewCertificate      []byte
}

// SignFlags is the input flags to Sign
type SignFlags uint32

// SignReq is the input request to Sign
type SignReq[Digest DigestAlgorithm] struct {
	ContextHandle ContextHandle
	Label         Digest
	Flags         SignFlags
	ToBeSigned    Digest
}

// SignResp is the output response from Sign
type SignResp[Digest DigestAlgorithm] struct {
	NewContextHandle ContextHandle
	SignatureR       Digest
	SignatureS       Digest
}

// DPEABI is a connection to a DPE instance, parameterized by hash algorithm and ECC curve.
type DPEABI[CurveParameter Curve, Digest DigestAlgorithm, Cert DPECertificate] struct {
	transport    Transport
	constants    profileInfo
	Profile      Profile
	MajorVersion uint16
	MinorVersion uint16
	VendorID     uint32
	VendorSku    uint32
	MaxTciNodes  uint32
	Flags        uint32
}

// DPEABI256 is a client that implements DPE_PROFILE_IROT_P256_SHA256
type DPEABI256Min = DPEABI[NISTP256Parameter, SHA256Digest, DPEMinCertificate]

// DPEABI384 is a client that implements DPE_PROFILE_IROT_P384_SHA384
type DPEABI384Min = DPEABI[NISTP384Parameter, SHA384Digest, DPEMinCertificate]

// DPEABI256 is a client that implements DPE_PROFILE_IROT_P256_SHA256
type DPEABI256 = DPEABI[NISTP256Parameter, SHA256Digest, DPEFullCertificate]

// DPEABI384 is a client that implements DPE_PROFILE_IROT_P384_SHA384
type DPEABI384 = DPEABI[NISTP384Parameter, SHA384Digest, DPEFullCertificate]

// dpeProfileImplementsTypeConstraints checks that the requested DPEABI type constraints are compatible with the DPE profile.
func dpeProfileImplementsTypeConstraints[C Curve, D DigestAlgorithm, Cert DPECertificate](profile Profile) error {
	// Test that the expected value types produced by each DPE profile can be assigned to variables of type C and D
	var c C
	var d D
	var cert Cert

	var targetProfile Profile
	_, isP256 := any(c).(NISTP256Parameter)
	_, isSHA256 := any(d).(SHA256Digest)
	_, isP384 := any(c).(NISTP384Parameter)
	_, isSHA384 := any(d).(SHA384Digest)
	_, isMin := any(cert).(DPEMinCertificate)

	if isP256 && isSHA256 && isMin {
		targetProfile = ProfileMinP256SHA256
	} else if isP384 && isSHA384 && isMin {
		targetProfile = ProfileMinP384SHA384
	} else if isP256 && isSHA256 && !isMin {
		targetProfile = ProfileP256SHA256
	} else if isP384 && isSHA384 && !isMin {
		targetProfile = ProfileP384SHA384
	} else {
		return fmt.Errorf("client requested (Curve = %v, Digest = %v, Certificate = %v), this is an invalid DPE profile",
			reflect.TypeOf(c), reflect.TypeOf(d), reflect.TypeOf(cert))
	}

	if profile != targetProfile {
		return fmt.Errorf("expected profile %v, got profile %v", targetProfile, profile)
	}

	return nil
}

// newDPEABI initializes a new DPE client.
func newDPEABI[C Curve, D DigestAlgorithm, Cert DPECertificate](t Transport) (*DPEABI[C, D, Cert], error) {
	rsp, err := getProfile(t)
	if err != nil {
		return nil, fmt.Errorf("could not query DPE for profile: %w", err)
	}

	if err := dpeProfileImplementsTypeConstraints[C, D, Cert](rsp.Profile); err != nil {
		return nil, err
	}

	var constants profileInfo
	if rsp.MajorVersion == 0 && rsp.MinorVersion == 8 {
		constants = getProfileInfoV08()
	} else if rsp.MajorVersion == 0 && rsp.MinorVersion >= 9 {
		// All current versions >= 9 use the same constants
		constants = getProfileInfoV09()
	} else {
		return nil, fmt.Errorf("unknown DPE profile version %d.%d", rsp.MajorVersion, rsp.MinorVersion)
	}

	return &DPEABI[C, D, Cert]{
		transport:    t,
		constants:    constants,
		Profile:      rsp.Profile,
		MajorVersion: rsp.MajorVersion,
		MinorVersion: rsp.MinorVersion,
		VendorID:     rsp.VendorID,
		VendorSku:    rsp.VendorSku,
		Flags:        rsp.Flags,
	}, nil
}

// NewDPEABI256 is a convenience wrapper for NewDPEABI[NISTP256Parameter, SHA256Digest, DPEFullCertificate].
func NewDPEABI256(t Transport) (*DPEABI[NISTP256Parameter, SHA256Digest, DPEFullCertificate], error) {
	return newDPEABI[NISTP256Parameter, SHA256Digest, DPEFullCertificate](t)
}

// NewDPEABI384 is a convenience wrapper for NewDPEABI[NISTP384Parameter, SHA384Digest, DPEFullCertificate].
func NewDPEABI384(t Transport) (*DPEABI[NISTP384Parameter, SHA384Digest, DPEFullCertificate], error) {
	return newDPEABI[NISTP384Parameter, SHA384Digest, DPEFullCertificate](t)
}

// NewDPEABI256Min is a convenience wrapper for NewDPEABI[NISTP256Parameter, SHA256Digest, DPEMinCertificate].
func NewDPEABI256Min(t Transport) (*DPEABI[NISTP256Parameter, SHA256Digest, DPEMinCertificate], error) {
	return newDPEABI[NISTP256Parameter, SHA256Digest, DPEMinCertificate](t)
}

// NewDPEABI384Min is a convenience wrapper for NewDPEABI[NISTP384Parameter, SHA384Digest, DPEMinCertificate].
func NewDPEABI384Min(t Transport) (*DPEABI[NISTP384Parameter, SHA384Digest, DPEMinCertificate], error) {
	return newDPEABI[NISTP384Parameter, SHA384Digest, DPEMinCertificate](t)
}

// InitializeContextABI calls InitializeContext
func (c *DPEABI[_, _, _]) InitializeContextABI(cmd *InitCtxCmd) (*InitCtxResp, error) {
	var respStruct InitCtxResp

	if _, err := execCommand(c.transport, c.constants.Codes.InitializeContext, c.Profile, cmd, &respStruct); err != nil {
		return nil, err
	}

	return &respStruct, nil
}

// GetTransportProfile gets the profile for transport `t`
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
		VendorID     uint32
		VendorSku    uint32
		MaxTciNodes  uint32
		Flags        uint32
	}{}

	// GetProfile command code is 1 in all revisions of the spec
	getProfile := CommandCode(0x1)
	respHdr, err := execCommand(t, getProfile, 0, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &GetProfileResp{
		// Special case for GetProfile: copy the profile from the inner packet header into the response structure.
		Profile:      respHdr.Profile,
		MajorVersion: respStruct.MajorVersion,
		MinorVersion: respStruct.MinorVersion,
		VendorID:     respStruct.VendorID,
		VendorSku:    respStruct.VendorSku,
		MaxTciNodes:  respStruct.MaxTciNodes,
		Flags:        respStruct.Flags,
	}, nil
}

// GetProfileABI calls the DPE GetProfile for this ABI
func (c *DPEABI[_, _, _]) GetProfileABI() (*GetProfileResp, error) {
	return getProfile(c.transport)
}

// DestroyContextABI calls the DPE DestroyContext for this ABI
func (c *DPEABI[_, _, _]) DestroyContextABI(cmd *DestroyCtxCmd) error {
	// DestroyContext does not return any parameters.
	respStruct := struct{}{}

	if _, err := execCommand(c.transport, c.constants.Codes.DestroyContext, c.Profile, cmd, &respStruct); err != nil {
		return err
	}

	return nil
}

// CertifyKeyABI calls the DPE CertifyKey command.
func (c *DPEABI[CurveParameter, Digest, DPECertificate]) CertifyKeyABI(cmd *CertifyKeyReq[Digest]) (*CertifyKeyResp[CurveParameter, Digest], error) {
	// Define an anonymous struct for the response, because we have to accept the variable-sized certificate.
	respStruct := struct {
		NewContextHandle  [16]byte
		DerivedPublicKeyX CurveParameter
		DerivedPublicKeyY CurveParameter
		CertificateSize   uint32
		Certificate       DPECertificate
	}{}

	_, err := execCommand(c.transport, c.constants.Codes.CertifyKey, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	// Check that the reported cert size makes sense.
	if respStruct.CertificateSize > uint32(CertLen[DPECertificate]()) {
		return nil, fmt.Errorf("DPE reported a %d-byte cert, which was larger than 2048", respStruct.CertificateSize)
	}

	return &CertifyKeyResp[CurveParameter, Digest]{
		NewContextHandle:  respStruct.NewContextHandle,
		DerivedPublicKeyX: respStruct.DerivedPublicKeyX,
		DerivedPublicKeyY: respStruct.DerivedPublicKeyY,
		Certificate:       respStruct.Certificate.Bytes()[:respStruct.CertificateSize],
	}, nil
}

// GetCertificateChainABI calls the DPE GetCertificateChain command.
func (c *DPEABI[_, _, _]) GetCertificateChainABI() (*GetCertificateChainResp, error) {
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

		_, err := execCommand(c.transport, c.constants.Codes.GetCertificateChain, c.Profile, cmd, &respStruct)
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
		return nil, fmt.Errorf("empty certificate chain returned")
	}
	return &certs, nil
}

// DeriveContextABI calls DPE DeriveContext command.
func (c *DPEABI[_, Digest, DPECertificate]) DeriveContextABI(cmd *DeriveContextReq[Digest]) (*DeriveContextResp, error) {
	// Define an anonymous struct for the response, because the shape changes if exportCdi is set.
	if cmd.Flags&CdiExport == CdiExport {
		respStruct := struct {
			NewContextHandle    [16]byte
			ParentContextHandle [16]byte
			ExportedCdi         [32]byte
			CertificateSize     uint32
			Certificate         DPECertificate
		}{}
		_, err := execCommand(c.transport, c.constants.Codes.DeriveContext, c.Profile, cmd, &respStruct)
		if err != nil {
			return nil, err
		}

		return &DeriveContextResp{
			NewContextHandle:    respStruct.NewContextHandle,
			ParentContextHandle: respStruct.ParentContextHandle,
			ExportedCdi:         respStruct.ExportedCdi,
			CertificateSize:     respStruct.CertificateSize,
			NewCertificate:      respStruct.Certificate.Bytes()[:respStruct.CertificateSize],
		}, nil
	} else {
		respStruct := struct {
			NewContextHandle    [16]byte
			ParentContextHandle [16]byte
		}{}
		_, err := execCommand(c.transport, c.constants.Codes.DeriveContext, c.Profile, cmd, &respStruct)
		if err != nil {
			return nil, err
		}

		return &DeriveContextResp{
			NewContextHandle:    respStruct.NewContextHandle,
			ParentContextHandle: respStruct.ParentContextHandle,
		}, nil
	}
}

// RotateContextHandleABI calls DPE RotateContextHandle command.
func (c *DPEABI[_, Digest, _]) RotateContextABI(cmd *RotateContextHandleCmd) (*RotatedContextHandle, error) {
	var respStruct RotatedContextHandle

	_, err := execCommand(c.transport, c.constants.Codes.RotateContextHandle, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, err
}

// SignABI calls the DPE Sign command.
func (c *DPEABI[_, Digest, _]) SignABI(cmd *SignReq[Digest]) (*SignResp[Digest], error) {
	var respStruct SignResp[Digest]

	_, err := execCommand(c.transport, c.constants.Codes.Sign, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, nil
}

// InitializeContext calls the DPE InitializeContext command
func (c *DPEABI[_, _, _]) InitializeContext(flags InitCtxFlags) (*ContextHandle, error) {
	cmd := InitCtxCmd{flags: flags}
	resp, err := c.InitializeContextABI(&cmd)
	if err != nil {
		return nil, err
	}

	return &resp.Handle, nil
}

// GetProfile calls the DPE GetProfile command
func (c *DPEABI[_, _, _]) GetProfile() (*GetProfileResp, error) {
	return c.GetProfileABI()
}

// CertifyKey calls the DPE CertifyKey command
func (c *DPEABI[_, Digest, _]) CertifyKey(handle *ContextHandle, label []byte, format CertifyKeyFormat, flags CertifyKeyFlags) (*CertifiedKey, error) {
	if len(label) != DigestLen[Digest]() {
		return nil, fmt.Errorf("invalid label length")
	}

	l, err := NewDigest[Digest](label)
	if err != nil {
		return nil, err
	}

	cmd := CertifyKeyReq[Digest]{
		ContextHandle: *handle,
		Flags:         flags,
		Label:         l,
		Format:        format,
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

// DestroyContext calls DPE DestroyContext command
func (c *DPEABI[_, _, _]) DestroyContext(handle *ContextHandle) error {
	cmd := DestroyCtxCmd{
		handle: *handle,
	}

	return c.DestroyContextABI(&cmd)
}

// GetCertificateChain calls DPE GetCertificateChain command
func (c *DPEABI[_, _, _]) GetCertificateChain() ([]byte, error) {
	resp, err := c.GetCertificateChainABI()
	if err != nil {
		return nil, err
	}

	return resp.CertificateChain, nil
}

// DeriveContext calls DPE DeriveContext command
func (c *DPEABI[_, Digest, _]) DeriveContext(handle *ContextHandle, inputData []byte, flags DeriveContextFlags, tciType uint32, targetLocality uint32) (*DeriveContextResp, error) {
	if len(inputData) != DigestLen[Digest]() {
		return nil, fmt.Errorf("invalid digest length")
	}

	input, err := NewDigest[Digest](inputData)
	if err != nil {
		return nil, err
	}

	cmd := DeriveContextReq[Digest]{
		ContextHandle:  *handle,
		InputData:      input,
		Flags:          flags,
		TciType:        tciType,
		TargetLocality: targetLocality,
	}
	resp, err := c.DeriveContextABI(&cmd)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// RotateContextHandle calls DPE RotateContextHandle command
func (c *DPEABI[_, _, _]) RotateContextHandle(handle *ContextHandle, flags RotateContextHandleFlags) (*ContextHandle, error) {
	cmd := RotateContextHandleCmd{
		Handle: *handle,
		Flags:  flags,
	}
	resp, err := c.RotateContextABI(&cmd)
	if err != nil {
		return nil, err
	}
	return &resp.NewContextHandle, nil
}

// Sign calls DPE Sign command
func (c *DPEABI[_, Digest, _]) Sign(handle *ContextHandle, label []byte, flags SignFlags, toBeSigned []byte) (*DPESignedHash, error) {
	dLen := DigestLen[Digest]()
	if len(label) != dLen {
		return nil, fmt.Errorf("invalid label length")
	}

	if len(toBeSigned) != dLen {
		return nil, fmt.Errorf("invalid toBeSigned length")
	}

	l, err := NewDigest[Digest](label)
	if err != nil {
		return nil, err
	}

	tbs, err := NewDigest[Digest](toBeSigned)
	if err != nil {
		return nil, err
	}

	cmd := SignReq[Digest]{
		ContextHandle: *handle,
		Label:         l,
		Flags:         flags,
		ToBeSigned:    tbs,
	}
	resp, err := c.SignABI(&cmd)
	if err != nil {
		return nil, err
	}

	signedResp := &DPESignedHash{
		Handle:     resp.NewContextHandle,
		SignatureR: resp.SignatureR.Bytes(),
		SignatureS: resp.SignatureS.Bytes(),
	}

	return signedResp, nil
}

// ToFlags converts support to the profile-defined support flags format
func (s *Support) ToFlags() uint32 {
	flags := uint32(0)
	if s.Simulation {
		flags |= (1 << 31)
	}
	if s.Recursive {
		flags |= (1 << 30)
	}
	if s.AutoInit {
		flags |= (1 << 29)
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
		flags |= (1 << 22)
	}
	if s.InternalDice {
		flags |= (1 << 21)
	}
	if s.IsCA {
		flags |= (1 << 20)
	}
	if s.RetainParentContext {
		flags |= (1 << 19)
	}
	if s.CdiExport {
		flags |= (1 << 18)
	}
	return flags
}
