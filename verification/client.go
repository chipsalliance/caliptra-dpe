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
	// If power control is unavailable for the given device, return false from
	// HasPowerControl and return an error from PowerOn and PowerOff. For devices
	// that don't support power control but do have reset capability, return true
	// from HasPowerControl leave PowerOn empty and execute the reset in PowerOff.
	HasPowerControl() bool
	// If supported, turns on the device or starts the emulator/simulator.
	PowerOn() error
	// If supported, turns of the device, stops the emulator/simulator, or resets.
	PowerOff() error
	// Send a command to the DPE instance.
	SendCmd(buf []byte) (error, []byte)
	// The Transport implementations are not expected to be able to set the values
	// it supports, but this function is used by tests to know how to test the DPE
	// instance.
	GetSupport() Support
}

type DpeClient struct {
	transport Transport
	profile   uint32
}

func (c *DpeClient) Initialize(locality uint32, cmd *InitCtxCmd) (error, RespHdr, InitCtxResp) {
	hdr := CommandHdr{
		magic:   CmdMagic,
		cmd:     InitCtxCode,
		profile: c.profile,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, locality)
	binary.Write(buf, binary.LittleEndian, hdr)
	binary.Write(buf, binary.LittleEndian, cmd)

	err, resp := c.transport.SendCmd(buf.Bytes())
	if err != nil {
		return err, RespHdr{}, InitCtxResp{}
	}

	respHdr := RespHdr{}
	respStruct := InitCtxResp{}

	r := bytes.NewReader(resp)
	binary.Read(r, binary.LittleEndian, &respHdr)
	err = c.checkRespHdr(respHdr)
	if err != nil {
		return err, RespHdr{}, InitCtxResp{}
	}

	binary.Read(r, binary.LittleEndian, &respStruct)

	return nil, respHdr, respStruct
}

func (c *DpeClient) GetProfile(locality uint32) (error, RespHdr, GetProfileResp) {
	hdr := CommandHdr{
		magic: CmdMagic,
		cmd:   GetProfileCode,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, locality)
	binary.Write(buf, binary.LittleEndian, hdr)

	err, resp := c.transport.SendCmd(buf.Bytes())
	if err != nil {
		return err, RespHdr{}, GetProfileResp{}
	}

	respHdr := RespHdr{}
	respStruct := GetProfileResp{}

	r := bytes.NewReader(resp)
	binary.Read(r, binary.LittleEndian, &respHdr)
	err = c.checkRespHdr(respHdr)
	if err != nil {
		return err, RespHdr{}, GetProfileResp{}
	}

	binary.Read(r, binary.LittleEndian, &respStruct)
	if respHdr.Status == 0 {
		c.profile = respHdr.Profile
	}

	return nil, respHdr, respStruct
}

// Check that the response header has all expected values and did not have any
// errors.
func (c *DpeClient) checkRespHdr(hdr RespHdr) error {
	if hdr.Magic != RespMagic {
		fmt.Println(hdr)
		return errors.New("Invalid response magic value.")
	}
	return nil
}
