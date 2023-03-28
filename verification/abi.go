package verification

const (
	CmdMagic  uint32 = 0x44504543
	RespMagic uint32 = 0x44504552

	DPE_PROFILE_P256_SHA256 uint32 = 1
	DPE_PROFILE_P384_SHA384 uint32 = 2

	CURRENT_PROFILE_VERSION uint32 = 0
)

type CommandCode uint32

const (
	CommandGetProfile        CommandCode = 0x1
	CommandInitializeContext CommandCode = 0x5
	CommandDestroyContext    CommandCode = 0xf
)

type CommandHdr struct {
	magic   uint32
	cmd     CommandCode
	profile uint32
}

type RespHdr struct {
	Magic   uint32
	Status  Status
	Profile uint32
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

type DestroyCtxCmd struct {
	handle [16]byte
	flags  uint32
}

func NewDestroyCtx(handle [16]byte, destroy_descendants bool) *DestroyCtxCmd {
	flags := uint32(0)
	if destroy_descendants {
		flags |= 1 << 31
	}
	return &DestroyCtxCmd{handle: handle, flags: flags}
}

type InitCtxResp struct {
	Handle [16]byte
}

type GetProfileResp struct {
	Profile     uint32
	Version     uint32
	MaxTciNodes uint32
	Flags       uint32
}
