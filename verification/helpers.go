package verification

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// checkRespHdr checks that the response header has all expected values and did not indicate an error.
func checkRespHdr(hdr RespHdr) error {
	if hdr.Magic != RespMagic {
		fmt.Println(hdr)
		return errors.New("invalid response magic value")
	}
	if hdr.Status != 0 {
		return Status(hdr.Status)
	}
	return nil
}

// execCommand executes the command. It returns the response header in the case of success, for internal use (i.e., GetProfile).
// cmd must be a struct of fixed-size values (or pointer to such), and rsp must be a pointer to such a struct.
func execCommand(t Transport, code CommandCode, profile uint32, cmd any, rsp any) (*RespHdr, error) {
	hdr := CommandHdr{
		magic:   CmdMagic,
		cmd:     code,
		profile: profile,
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, hdr)
	binary.Write(buf, binary.LittleEndian, cmd)

	err, resp := t.SendCmd(buf.Bytes())
	if err != nil {
		return nil, err
	}

	respHdr := RespHdr{}

	r := bytes.NewReader(resp)
	if err = binary.Read(r, binary.LittleEndian, &respHdr); err != nil {
		return nil, err
	}
	if err = checkRespHdr(respHdr); err != nil {
		return nil, err
	}

	if err = binary.Read(r, binary.LittleEndian, rsp); err != nil {
		return nil, err
	}

	return &respHdr, nil
}
