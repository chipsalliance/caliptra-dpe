package verification

import (
	"errors"
	"net"
)

type SimulatorTransport struct {
	Transport
}

func (s *SimulatorTransport) SendCmd(buf []byte) (error, []byte) {
	// Connect to DPE instance.
	conn, err := net.Dial("unix", "/tmp/dpe-sim.socket")
	if err != nil {
		return err, []byte{}
	}

	// Send the command.
	num_sent, err := conn.Write(buf)
	if err != nil {
		return err, []byte{}
	}
	if num_sent != len(buf) {
		return errors.New("Didn't send the whole command."), []byte{}
	}

	// Get the response.
	num_rec, err := conn.Read(buf)
	if err != nil {
		return err, []byte{}
	}
	if num_rec == 0 {
		return errors.New("Didn't receive anything in the response."), []byte{}
	}

	return nil, buf
}
