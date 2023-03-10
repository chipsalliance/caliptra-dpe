package verification

const (
	CmdMagic  uint32 = 0x44504543
	RespMagic uint32 = 0x44504552

	GetProfileCode uint32 = 0x1
	InitCtxCode    uint32 = 0x5

	DPE_PROFILE_P256_SHA256 uint32 = 1
	DPE_PROFILE_P384_SHA384 uint32 = 2

	DPE_STATUS_SUCCESS                uint32 = 0
	DPE_STATUS_INTERNAL_ERROR         uint32 = 1
	DPE_STATUS_INVALID_COMMAND        uint32 = 2
	DPE_STATUS_INVALID_ARGUMENT       uint32 = 3
	DPE_STATUS_ARGUMENT_NOT_SUPPORTED uint32 = 4
	DPE_STATUS_INVALID_HANDLE         uint32 = 0x1000
	DPE_STATUS_INVALID_DOMAIN         uint32 = 0x1001
	DPE_STATUS_BAD_TAG                uint32 = 0x1002
	DPE_STATUS_HANDLE_DEFINED         uint32 = 0x1003
	DPE_STATUS_MAX_TCIS               uint32 = 0x1004
)

type CommandHdr struct {
	magic   uint32
	cmd     uint32
	profile uint32
}

type RespHdr struct {
	Magic   uint32
	Status  uint32
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

type InitCtxResp struct {
	Handle [16]byte
}

type GetProfileResp struct {
	Version     uint32
	MaxTciNodes uint32
	Flags       uint32
}
