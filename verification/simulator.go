package verification

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	socketPath = "/tmp/dpe-sim.socket"

	DPE_SIMULATOR_AUTO_INIT_LOCALITY uint32 = 0
	DPE_SIMULATOR_OTHER_LOCALITY     uint32 = 0x4f544852
	DPE_SIMULATOR_PROFILE            uint32 = DPE_PROFILE_P256_SHA256
	DPE_SIMULATOR_MAX_TCI_NODES      uint32 = 24
	DPE_SIMULATOR_PROFILE_VERSION    uint32 = CURRENT_PROFILE_VERSION
)

type DpeSimulator struct {
	exe_path        string
	cmd             *exec.Cmd
	supports        Support
	currentLocality uint32
	Transport
}

// Simulator can be started and stopped.
func (s *DpeSimulator) HasPowerControl() bool {
	return true
}

// Start the simulator.
func (s *DpeSimulator) PowerOn() error {
	args := []string{}
	if s.supports.Simulation {
		args = append(args, "--supports-simulation")
	}
	if s.supports.ExtendTci {
		args = append(args, "--supports-extend-tci")
	}
	if s.supports.AutoInit {
		args = append(args, "--supports-auto-init")
	}
	if s.supports.Tagging {
		args = append(args, "--supports-tagging")
	}
	if s.supports.RotateContext {
		args = append(args, "--supports-rotate-context")
	}

	s.cmd = exec.Command(s.exe_path, args...)
	s.cmd.Stdout = os.Stdout
	err := s.cmd.Start()
	if err != nil {
		return err
	}
	if !s.waitForPower( /*on=*/ true) {
		return errors.New("the simulator never started")
	}
	return nil
}

// Kill the simulator in a way that it can cleanup before closing.
func (s *DpeSimulator) PowerOff() error {
	if s.cmd != nil {
		err := s.cmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			return err
		}
		if !s.waitForPower( /*on=*/ false) {
			return errors.New("the simulator never stopped")
		}
	}
	return nil
}

// Wait for the simulator to come alive. Timeout at 15 seconds.
func (s *DpeSimulator) waitForPower(on bool) bool {
	timeout_seconds := 15
	checks_per_sec := 50

	for i := 0; i < checks_per_sec*timeout_seconds; i++ {
		// Check if the socket file has been created.
		if fileExists(socketPath) == on {
			return true
		}
		time.Sleep(time.Duration(1000/checks_per_sec) * time.Millisecond)
	}
	return false
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func (s *DpeSimulator) SendCmd(buf []byte) ([]byte, error) {
	// Connect to DPE instance.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}

	// Prepend the command with the locality.
	prepended := bytes.NewBuffer(make([]byte, 0, 4+len(buf)))
	if err := binary.Write(prepended, binary.LittleEndian, s.currentLocality); err != nil {
		return nil, err
	}
	if _, err := prepended.Write(buf); err != nil {
		return nil, err
	}

	// Send the prepended command.
	num_sent, err := conn.Write(prepended.Bytes())
	if err != nil {
		return nil, err
	}
	if num_sent != len(prepended.Bytes()) {
		return nil, errors.New("didn't send the whole command")
	}

	// Get the response.
	return io.ReadAll(conn)
}

func (s *DpeSimulator) GetSupport() *Support {
	return &s.supports
}

func (s *DpeSimulator) GetProfile() uint32 {
	return DPE_SIMULATOR_PROFILE
}

func (s *DpeSimulator) GetSupportedLocalities() []uint32 {
	return []uint32{DPE_SIMULATOR_AUTO_INIT_LOCALITY, DPE_SIMULATOR_OTHER_LOCALITY}
}

func (s *DpeSimulator) SetLocality(locality uint32) {
	s.currentLocality = locality
}

func (s *DpeSimulator) GetLocality() uint32 {
	return s.currentLocality
}

func (s *DpeSimulator) GetMaxTciNodes() uint32 {
	return DPE_SIMULATOR_MAX_TCI_NODES
}

func (s *DpeSimulator) GetProfileVersion() uint32 {
	return DPE_SIMULATOR_PROFILE_VERSION
}
