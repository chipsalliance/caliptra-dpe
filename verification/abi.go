// Licensed under the Apache-2.0 license

package verification

const (
	CmdMagic  uint32 = 0x44504543
	RespMagic uint32 = 0x44504552

	CURRENT_PROFILE_MAJOR_VERSION uint16 = 0
	CURRENT_PROFILE_MINOR_VERSION uint16 = 8
)

type CommandCode uint32

const (
	CommandGetProfile        CommandCode = 0x1
	CommandInitializeContext CommandCode = 0x7
	CommandCertifyKey        CommandCode = 0x9
	CommandDestroyContext    CommandCode = 0xf
	CommandTagTCI            CommandCode = 0x82
	CommandGetTaggedTCI      CommandCode = 0x83
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
	flags uint32
}

func NewInitCtxIsDefault() *InitCtxCmd {
	return &InitCtxCmd{flags: 1 << 30}
}

func NewInitCtxIsSimulation() *InitCtxCmd {
	return &InitCtxCmd{flags: 1 << 31}
}

type ContextHandle [16]byte

type DestroyCtxCmd struct {
	handle ContextHandle
	flags  uint32
}

func NewDestroyCtx(handle ContextHandle, destroy_descendants bool) *DestroyCtxCmd {
	flags := uint32(0)
	if destroy_descendants {
		flags |= 1 << 31
	}
	return &DestroyCtxCmd{handle: handle, flags: flags}
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
