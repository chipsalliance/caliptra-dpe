// Licensed under the Apache-2.0 license

package verification

import (
	"fmt"
	"reflect"
)

// DefaultContextHandle is the default DPE context handle
var DefaultContextHandle = ContextHandle{0}
var InvalidatedContextHandle = ContextHandle{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}

// Profile-defined constants
const (
	CmdMagic  uint32 = 0x44504543
	RespMagic uint32 = 0x44504552

	CurrentProfileMajorVersion uint16 = 0
	CurrentProfileMinorVersion uint16 = 8
)

// CommandCode is a DPE command code
type CommandCode uint32

// Support is the set of features a DPE supports
type Support struct {
	Simulation    bool
	ExtendTci     bool
	AutoInit      bool
	RotateContext bool
	X509          bool
	Csr           bool
	IsSymmetric   bool
	InternalInfo  bool
	InternalDice  bool
	IsCA          bool
}

// All DPE profile command codes
const (
	CommandGetProfile          CommandCode = 0x1
	CommandInitializeContext   CommandCode = 0x7
	CommandDeriveChild         CommandCode = 0x8
	CommandCertifyKey          CommandCode = 0x9
	CommandSign                CommandCode = 0xa
	CommandRotateContextHandle CommandCode = 0xe
	CommandDestroyContext      CommandCode = 0xf
	CommandGetCertificateChain CommandCode = 0x80
	CommandExtendTCI           CommandCode = 0x81
)

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

// DestroyCtxFlags is input flags to DestroyContext
type DestroyCtxFlags uint32

// Supported flags to DestroyContext
const (
	DestroyDescendants DestroyCtxFlags = 1 << 31
)

// DestroyCtxCmd is input parameters to DestroyContext
type DestroyCtxCmd struct {
	handle ContextHandle
	flags  DestroyCtxFlags
}

// NewDestroyCtx creates a new DestroyContext command
func NewDestroyCtx(handle ContextHandle, destroyDescendants bool) *DestroyCtxCmd {
	flags := DestroyCtxFlags(0)
	if destroyDescendants {
		flags |= DestroyDescendants
	}
	return &DestroyCtxCmd{handle: handle, flags: flags}
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

// Supported flags to CertifyKey
const (
	CertifyAddIsCA CertifyKeyFlags = 1 << 30
)

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
	Label         Digest
	Format        CertifyKeyFormat
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

// DeriveChildFlags is the input flags to DeriveChild
type DeriveChildFlags uint32

// Supported flags to DeriveChild
const (
	InternalInputInfo DeriveChildFlags = 1 << 31
	InternalInputDice DeriveChildFlags = 1 << 30
	RetainParent      DeriveChildFlags = 1 << 29
	MakeDefault       DeriveChildFlags = 1 << 28
	ChangeLocality    DeriveChildFlags = 1 << 27
	InputAllowCA      DeriveChildFlags = 1 << 26
	InputAllowX509    DeriveChildFlags = 1 << 25
)

// DeriveChildReq is the input request to DeriveChild
type DeriveChildReq[Digest DigestAlgorithm] struct {
	ContextHandle  ContextHandle
	InputData      Digest
	Flags          DeriveChildFlags
	TciType        uint32
	TargetLocality uint32
}

// DeriveChildResp is the output response from DeriveChild
type DeriveChildResp struct {
	NewContextHandle    ContextHandle
	ParentContextHandle ContextHandle
}

// SignFlags is the input flags to Sign
type SignFlags uint32

// Supported Sign flags
const (
	IsSymmetric SignFlags = 1 << 30
)

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
	HmacOrSignatureR Digest
	SignatureS       Digest
}

// ExtendTCIReq is the input request to ExtendTCI
type ExtendTCIReq[Digest DigestAlgorithm] struct {
	ContextHandle ContextHandle
	InputData     Digest
}

// ExtendTCIResp is the output response from ExtendTCI
type ExtendTCIResp struct {
	NewContextHandle ContextHandle
}

// DPEABI is a connection to a DPE instance, parameterized by hash algorithm and ECC curve.
type DPEABI[CurveParameter Curve, Digest DigestAlgorithm] struct {
	transport    Transport
	Profile      Profile
	MajorVersion uint16
	MinorVersion uint16
	VendorID     uint32
	VendorSku    uint32
	MaxTciNodes  uint32
	Flags        uint32
}

// DPEABI256 is a client that implements DPE_PROFILE_IROT_P256_SHA256
type DPEABI256 = DPEABI[NISTP256Parameter, SHA256Digest]

// DPEABI384 is a client that implements DPE_PROFILE_IROT_P384_SHA384
type DPEABI384 = DPEABI[NISTP384Parameter, SHA384Digest]

// dpeProfileImplementsTypeConstraints checks that the requested DPEABI type constraints are compatible with the DPE profile.
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
		return fmt.Errorf("client requested (Curve = %v, Digest = %v), this is an invalid DPE profile",
			reflect.TypeOf(c), reflect.TypeOf(d))
	}

	if profile != targetProfile {
		return fmt.Errorf("expected profile %v, got profile %v", targetProfile, profile)
	}

	return nil
}

// newDPEABI initializes a new DPE client.
func newDPEABI[C Curve, D DigestAlgorithm](t Transport) (*DPEABI[C, D], error) {
	rsp, err := getProfile(t)
	if err != nil {
		return nil, fmt.Errorf("could not query DPE for profile: %w", err)
	}

	if err := dpeProfileImplementsTypeConstraints[C, D](rsp.Profile); err != nil {
		return nil, err
	}

	return &DPEABI[C, D]{
		transport:    t,
		Profile:      rsp.Profile,
		MajorVersion: rsp.MajorVersion,
		MinorVersion: rsp.MinorVersion,
		VendorID:     rsp.VendorID,
		VendorSku:    rsp.VendorSku,
		Flags:        rsp.Flags,
	}, nil
}

// NewDPEABI256 is a convenience wrapper for NewDPEABI[NISTP256Parameter, SHA256Digest].
func NewDPEABI256(t Transport) (*DPEABI[NISTP256Parameter, SHA256Digest], error) {
	return newDPEABI[NISTP256Parameter, SHA256Digest](t)
}

// NewDPEABI384 is a convenience wrapper for NewDPEABI[NISTP384Parameter, SHA384Digest].
func NewDPEABI384(t Transport) (*DPEABI[NISTP384Parameter, SHA384Digest], error) {
	return newDPEABI[NISTP384Parameter, SHA384Digest](t)
}

// InitializeContextABI calls InitializeContext
func (c *DPEABI[_, _]) InitializeContextABI(cmd *InitCtxCmd) (*InitCtxResp, error) {
	var respStruct InitCtxResp

	if _, err := execCommand(c.transport, CommandInitializeContext, c.Profile, cmd, &respStruct); err != nil {
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

	respHdr, err := execCommand(t, CommandGetProfile, 0, cmd, &respStruct)
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

func (c *DPEABI[_, _]) GetProfileABI() (*GetProfileResp, error) {
	return getProfile(c.transport)
}

// Send the command to destroy a context.
func (c *DPEABI[_, _]) DestroyContextABI(cmd *DestroyCtxCmd) error {
	// DestroyContext does not return any parameters.
	respStruct := struct{}{}

	if _, err := execCommand(c.transport, CommandDestroyContext, c.Profile, cmd, &respStruct); err != nil {
		return err
	}

	return nil
}

// CertifyKey calls the DPE CertifyKey command.
func (c *DPEABI[CurveParameter, Digest]) CertifyKeyABI(cmd *CertifyKeyReq[Digest]) (*CertifyKeyResp[CurveParameter, Digest], error) {
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

// GetCertificateChain calls the DPE GetCertificateChain command.
func (c *DPEABI[_, _]) GetCertificateChainABI() (*GetCertificateChainResp, error) {
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
		return nil, fmt.Errorf("empty certificate chain returned")
	}
	return &certs, nil
}

// DeriveChild calls DPE DeriveChild command.
func (c *DPEABI[_, Digest]) DeriveChildABI(cmd *DeriveChildReq[Digest]) (*DeriveChildResp, error) {
	var respStruct DeriveChildResp

	_, err := execCommand(c.transport, CommandDeriveChild, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, err
}

// RotateContextHandle calls DPE RotateContextHandle command.
func (c *DPEABI[_, Digest]) RotateContextABI(cmd *RotateContextHandleCmd) (*RotatedContextHandle, error) {
	var respStruct RotatedContextHandle

	_, err := execCommand(c.transport, CommandRotateContextHandle, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, err
}

// Sign calls the DPE Sign command.
func (c *DPEABI[_, Digest]) SignABI(cmd *SignReq[Digest]) (*SignResp[Digest], error) {
	var respStruct SignResp[Digest]

	_, err := execCommand(c.transport, CommandSign, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, nil
}

// ExtendTCI calls the DPE ExtendTCI command.
func (c *DPEABI[_, Digest]) ExtendTCIABI(cmd *ExtendTCIReq[Digest]) (*ExtendTCIResp, error) {
	var respStruct ExtendTCIResp

	_, err := execCommand(c.transport, CommandExtendTCI, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, nil
}

func (c *DPEABI[_, _]) InitializeContext(flags InitCtxFlags) (*ContextHandle, error) {
	cmd := InitCtxCmd{flags: flags}
	resp, err := c.InitializeContextABI(&cmd)
	if err != nil {
		return nil, err
	}

	return &resp.Handle, nil
}

func (c *DPEABI[_, _]) GetProfile() (*GetProfileResp, error) {
	return c.GetProfileABI()
}

func (c *DPEABI[_, Digest]) CertifyKey(handle *ContextHandle, label []byte, format CertifyKeyFormat, flags CertifyKeyFlags) (*CertifiedKey, error) {
	if len(label) != len(Digest(label)) {
		return nil, fmt.Errorf("invalid label length")
	}

	cmd := CertifyKeyReq[Digest]{
		ContextHandle: *handle,
		Flags:         flags,
		Label:         Digest(label),
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

func (c *DPEABI[_, _]) DestroyContext(handle *ContextHandle, flags DestroyCtxFlags) error {
	cmd := DestroyCtxCmd{
		handle: *handle,
		flags:  flags,
	}

	return c.DestroyContextABI(&cmd)
}

func (c *DPEABI[_, _]) GetCertificateChain() ([]byte, error) {
	resp, err := c.GetCertificateChainABI()
	if err != nil {
		return nil, err
	}

	return resp.CertificateChain, nil
}

func (c *DPEABI[_, Digest]) DeriveChild(handle *ContextHandle, inputData []byte, flags DeriveChildFlags, tciType uint32, targetLocality uint32) (*DeriveChildResp, error) {
	if len(inputData) != len(Digest(inputData)) {
		return nil, fmt.Errorf("invalid digest length")
	}

	cmd := DeriveChildReq[Digest]{
		ContextHandle:  *handle,
		InputData:      Digest(inputData),
		Flags:          flags,
		TciType:        tciType,
		TargetLocality: targetLocality,
	}
	resp, err := c.DeriveChildABI(&cmd)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *DPEABI[_, _]) RotateContextHandle(handle *ContextHandle, flags RotateContextHandleFlags) (*ContextHandle, error) {
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

func (c *DPEABI[_, Digest]) Sign(handle *ContextHandle, label []byte, flags SignFlags, toBeSigned []byte) (*DPESignedHash, error) {
	if len(label) != len(Digest(label)) {
		return nil, fmt.Errorf("invalid label length")
	}

	if len(toBeSigned) != len(Digest(toBeSigned)) {
		return nil, fmt.Errorf("invalid toBeSigned length")
	}

	cmd := SignReq[Digest]{
		ContextHandle: *handle,
		Label:         Digest(label),
		Flags:         flags,
		ToBeSigned:    Digest(toBeSigned),
	}
	resp, err := c.SignABI(&cmd)
	if err != nil {
		return nil, err
	}

	signedResp := &DPESignedHash{
		Handle:           resp.NewContextHandle,
		HmacOrSignatureR: resp.HmacOrSignatureR.Bytes(),
		SignatureS:       resp.SignatureS.Bytes(),
	}

	return signedResp, nil
}

func (c *DPEABI[_, Digest]) ExtendTCI(handle *ContextHandle, inputData []byte) (*ContextHandle, error) {

	if len(inputData) != len(Digest(inputData)) {
		return nil, fmt.Errorf("invalid digest length")
	}

	cmd := ExtendTCIReq[Digest]{
		ContextHandle: *handle,
		InputData:     Digest(inputData),
	}

	resp, err := c.ExtendTCIABI(&cmd)
	if err != nil {
		return nil, err
	}

	return &resp.NewContextHandle, nil
}

// ToFlags converts support to the profile-defined support flags format
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
	return flags
}
