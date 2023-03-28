package verification

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type Support struct {
	Simulation    bool
	ExtendTci     bool
	AutoInit      bool
	Tagging       bool
	RotateContext bool
}

// An interface to define how to test and send messages to a DPE instance.
type Transport interface {
	// Send a command to the DPE instance.
	SendCmd(buf []byte) (error, []byte)
}

type Client struct {
	transport Transport
	profile   uint32
}

// NewClient initializes a new DPE client, including querying the underlying implementation for its profile.
func NewClient(t Transport) (*Client, error) {
	client := Client{transport: t}
	rsp, err := client.GetProfile()
	if err != nil {
		return nil, fmt.Errorf("could not query DPE profile: %w", err)
	}
	client.profile = rsp.Profile
	return &client, nil
}

func (c *Client) InitializeContext(cmd *InitCtxCmd) (*InitCtxResp, error) {
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
		return nil, err
	}

	respHdr := RespHdr{}
	respStruct := InitCtxResp{}

	r := bytes.NewReader(resp)
	err = binary.Read(r, binary.LittleEndian, &respHdr)
	if err != nil {
		return nil, err
	}
	err = c.checkRespHdr(respHdr)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &respStruct)
	if err != nil {
		return nil, err
	}

	return &respStruct, nil
}

func (c *Client) GetProfile() (*GetProfileResp, error) {
	hdr := CommandHdr{
		magic: CmdMagic,
		cmd:   GetProfileCode,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, hdr)

	err, resp := c.transport.SendCmd(buf.Bytes())
	if err != nil {
		return nil, err
	}

	respHdr := RespHdr{}
	// Define an anonymous struct for the actual wire-format members of GetProfile,
	// since GetProfileResp includes the actual profile copied from the response header.
	respStruct := struct {
		Version     uint32
		MaxTciNodes uint32
		Flags       uint32
	}{}

	r := bytes.NewReader(resp)
	err = binary.Read(r, binary.LittleEndian, &respHdr)
	if err != nil {
		return nil, err
	}
	err = c.checkRespHdr(respHdr)
	if err != nil {
		return nil, err
	}

	err = binary.Read(r, binary.LittleEndian, &respStruct)
	if err != nil {
		return nil, err
	}

	return &GetProfileResp{
		// Special case for GetProfile: copy the profile from the inner packet header into the response structure.
		Profile:     respHdr.Profile,
		Version:     respStruct.Version,
		MaxTciNodes: respStruct.MaxTciNodes,
		Flags:       respStruct.Flags,
	}, nil
}

// Send the command to destroy a context.
func (c *Client) DestroyContext(cmd *DestroyCtxCmd) error {
	hdr := CommandHdr{
		magic:   CmdMagic,
		cmd:     DestroyCtxCode,
		profile: c.profile,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, hdr)
	binary.Write(buf, binary.LittleEndian, cmd)

	err, resp := c.transport.SendCmd(buf.Bytes())
	if err != nil {
		return err
	}

	respHdr := RespHdr{}

	r := bytes.NewReader(resp)
	err = binary.Read(r, binary.LittleEndian, &respHdr)
	if err != nil {
		return err
	}
	err = c.checkRespHdr(respHdr)
	if err != nil {
		return err
	}

	return nil
}

// checkRespHdr checks that the response header has all expected values and did not indicate an error.
func (c *Client) checkRespHdr(hdr RespHdr) error {
	if hdr.Magic != RespMagic {
		fmt.Println(hdr)
		return errors.New("invalid response magic value")
	}
	if hdr.Status != 0 {
		return Status(hdr.Status)
	}
	return nil
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
	return flags
}
