package verification

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type Transport interface {
	SendCmd(buf []byte) (error, []byte)
}

type DpeClient struct {
	transport Transport
	profile   uint32
}

func (c *DpeClient) Initialize(cmd *InitCtxCmd) (error, InitCtxResp) {
	hdr := CommandHdr{
		magic:   CmdMagic,
		cmd:     InitCtxCode,
		profile: c.profile,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, hdr)
	binary.Write(buf, binary.LittleEndian, cmd)

	err, resp := c.transport.SendCmd(buf.Bytes())
	if err != nil {
		return err, InitCtxResp{}
	}

	respHdr := RespHdr{}
	respStruct := InitCtxResp{}

	r := bytes.NewReader(resp)
	binary.Read(r, binary.LittleEndian, &respHdr)
	check_hdr_err := c.checkRespHdr(respHdr)
	if check_hdr_err != nil {
		return check_hdr_err, InitCtxResp{}
	}

	binary.Read(r, binary.LittleEndian, &respStruct)

	return nil, respStruct
}

func (c *DpeClient) GetProfile() (error, GetProfileResp) {
	hdr := CommandHdr{
		magic: CmdMagic,
		cmd:   GetProfileCode,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, hdr)

	err, resp := c.transport.SendCmd(buf.Bytes())
	if err != nil {
		return err, GetProfileResp{}
	}

	respHdr := RespHdr{}
	respStruct := GetProfileResp{}

	r := bytes.NewReader(resp)
	binary.Read(r, binary.LittleEndian, &respHdr)
	check_hdr_err := c.checkRespHdr(respHdr)
	if check_hdr_err != nil {
		return check_hdr_err, GetProfileResp{}
	}

	binary.Read(r, binary.LittleEndian, &respStruct)

	return nil, respStruct
}

// Check that the response header has all expected values and did not have any
// errors.
func (c *DpeClient) checkRespHdr(hdr RespHdr) error {
	if hdr.Magic != RespMagic {
		fmt.Println(hdr)
		return errors.New("Invalid response magic value.")
	}
	if hdr.Status != 0 {
		return errors.New("Received an error status.")
	}
	if hdr.Profile != c.profile {
		return errors.New("Incorrect profile value.")
	}
	return nil
}
