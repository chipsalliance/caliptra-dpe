package verification

const (
	CmdMagic  uint32 = 0x44504543
	RespMagic uint32 = 0x44504552

	GetProfileCode uint32 = 0x1
	InitCtxCode    uint32 = 0x5
)

type GetProfileHdr struct {
	magic uint32
	cmd   uint32
}

type CommandHdr struct {
	magic   uint32
	cmd     uint32
	profile uint32
}

type RespHdr struct {
	magic   uint32
	status  uint32
	profile uint32
}

type InitCtxCmd struct {
	flags uint32
}

type InitCtxResp struct {
	handle [20]byte
}

type GetProfileResp struct {
	version uint32
	flags   uint32
}
