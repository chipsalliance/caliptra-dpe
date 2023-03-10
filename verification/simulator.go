package verification

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	socketPath = "/tmp/dpe-sim.socket"
)

type DpeSimulator struct {
	exe_path string
	cmd      *exec.Cmd
	supports Support
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
		args = append(args, "--supports-extend_tci")
	}
	if s.supports.AutoInit {
		args = append(args, "--supports-auto_init")
	}
	if s.supports.Tagging {
		args = append(args, "--supports-tagging")
	}
	if s.supports.RotateContext {
		args = append(args, "--supports-rotate_context")
	}

	s.cmd = exec.Command(s.exe_path, args...)
	s.cmd.Stdout = os.Stdout
	err := s.cmd.Start()
	if err != nil {
		return err
	}
	if !s.waitForPower( /*on=*/ true) {
		return errors.New("The simulator never started")
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
			return errors.New("The simulator never stopped")
		}
	}
	return nil
}

// Wait for the simulator to come alive. Timeout at 15 seconds.
func (s *DpeSimulator) waitForPower(on bool) bool {
	timeout_seconds := 15
	checks_per_sec := 4

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

func (s *DpeSimulator) SendCmd(buf []byte) (error, []byte) {
	// Connect to DPE instance.
	conn, err := net.Dial("unix", socketPath)
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

func (s *DpeSimulator) GetSupport() Support {
	return s.supports
}
