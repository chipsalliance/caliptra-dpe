// Licensed under the Apache-2.0 license

//go:build linux

// Package google provides a DPE transport implementation for Google iRoT
// devices.
package google

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	// IRoTDPEIoctl is the IOCTL number exposed by the Google iRoT DPE driver.
	IRoTDPEIoctl = 0x1

	// DefaultIRoTDevicePath is the default character device path for the
	// Google iRoT DPE driver.
	DefaultIRoTDevicePath = "/dev/irot"

	// irotMaxRespSize is the maximum response buffer size in bytes for a
	// Google iRoT DPE command.
	irotMaxRespSize = 8192
)

// irotTransfer matches the kernel's struct dpe_ioctl / google_dpe_transfer
// on 64-bit Linux systems.
type irotTransfer struct {
	CmdBuf  uint64
	CmdLen  uint64
	RespBuf uint64
	RespLen uint64
}

// IRoTDPE implements the DPE Transport interface for Google iRoT devices
// using the Linux kernel DPE character device driver.
type IRoTDPE struct {
	device string
}

// NewIRoTDPE creates a Google iRoT transport with the default /dev/irot
// device file path.
func NewIRoTDPE() IRoTDPE {
	return IRoTDPE{
		device: DefaultIRoTDevicePath,
	}
}

// NewIRoTDPEWithDevice creates a Google iRoT transport with a device file
// at dev (e.g., "/dev/dpe" or "/dev/irot").
func NewIRoTDPEWithDevice(dev string) IRoTDPE {
	return IRoTDPE{
		device: dev,
	}
}

// SendCmd sends a DPE command to the Google iRoT kernel driver and returns the
// response payload. This implements client.Transport.
func (d IRoTDPE) SendCmd(buf []byte) ([]byte, error) {
	f, err := os.OpenFile(d.device, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open Google iRoT DPE device %q: %w", d.device, err)
	}
	defer f.Close()

	var cmdBufPtr uint64
	if len(buf) > 0 {
		cmdBufPtr = uint64(uintptr(unsafe.Pointer(&buf[0])))
	}

	respPayload := make([]byte, irotMaxRespSize)

	transfer := irotTransfer{
		CmdBuf:  cmdBufPtr,
		CmdLen:  uint64(len(buf)),
		RespBuf: uint64(uintptr(unsafe.Pointer(&respPayload[0]))),
		RespLen: uint64(len(respPayload)),
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(IRoTDPEIoctl),
		uintptr(unsafe.Pointer(&transfer)),
	)
	runtime.KeepAlive(buf)
	runtime.KeepAlive(respPayload)
	if errno != 0 {
		return nil, fmt.Errorf("Google iRoT DPE ioctl failed: %w", errno)
	}

	if transfer.RespLen > uint64(len(respPayload)) {
		return nil, fmt.Errorf("Google iRoT DPE command failed, insufficient response buffer")
	}
	return respPayload[:transfer.RespLen], nil
}
