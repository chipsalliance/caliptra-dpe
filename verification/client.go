package verification

import (
	"bytes"
	"encoding/binary"
)

type DpeClient struct {
}

func (c *DpeClient) Initialize(cmd *InitCtxCmd) (error, InitCtxResp) {
	hdr := CommandHdr{
		magic:   CmdMagic,
		cmd:     InitCtxCode,
		profile: 0,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, hdr)

	err, resp := c.sendCmd(buf.Bytes())
	if err != nil {
		return err, InitCtxResp{}
	}

	respHdr := RespHdr{}
	respStruct := InitCtxResp{}

	r := bytes.NewReader(resp)
	binary.Read(r, binary.LittleEndian, respHdr)

	binary.Read(r, binary.LittleEndian, respStruct)

	return nil, respStruct
}

func (c *DpeClient) GetProfile() (error, GetProfileResp) {
	hdr := GetProfileHdr{
		magic: CmdMagic,
		cmd:   GetProfileCode,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, hdr)

	err, resp := c.sendCmd(buf.Bytes())
	if err != nil {
		return err, GetProfileResp{}
	}

	respHdr := RespHdr{}
	respStruct := GetProfileResp{}

	r := bytes.NewReader(resp)
	binary.Read(r, binary.LittleEndian, respHdr)

	binary.Read(r, binary.LittleEndian, respStruct)

	return nil, respStruct
}

// Sends a DPE command and gets back a DPE response
func (c *DpeClient) sendCmd(buf []byte) (error, []byte) {
	return nil, [16]byte{}
}
