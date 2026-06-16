// Licensed under the Apache-2.0 license

package client

import "fmt"

// Status is a DPE status code
type Status uint32

// DPE status codes per the TCG DPE Specification, Section 5.11 (values 0-7)
// and the OCP "Server iRoT Profile for DPE" v0.13.0 (values 0x80+).
const (
	// TCG DPE Specification
	StatusInternalError          Status = 0x1
	StatusInvalidCommand         Status = 0x2
	StatusInvalidArgument        Status = 0x3
	StatusSessionExhausted       Status = 0x4
	StatusInitializationSeedLock Status = 0x5
	StatusOutOfMemory            Status = 0x6
	StatusCancelledCommand       Status = 0x7

	// OCP iRoT Profile for DPE
	StatusInvalidHandle         Status = 0x80
	StatusInvalidLocality       Status = 0x81
	StatusHandleDefined         Status = 0x82
	StatusArgumentNotSupported  Status = 0x83
	StatusAlreadyInitialized    Status = 0x84
	StatusInvalidParentLocality Status = 0x85

	// Vendor-defined (continuation of 0x80 range)
	StatusMaxTCIs Status = 0x91

	// Compound error bases
	StatusPlatformError   Status = 0x01000000
	StatusCryptoError     Status = 0x02000000
	StatusValidationError Status = 0x03000000
)

// Error returns an informational string for all DPE error codes
func (s Status) Error() string {
	switch s {
	case StatusInternalError:
		return "error internal to DPE"
	case StatusInvalidCommand:
		return "command ID is invalid"
	case StatusInvalidArgument:
		return "argument is invalid"
	case StatusSessionExhausted:
		return "session exhausted"
	case StatusInitializationSeedLock:
		return "initialization seed locked"
	case StatusOutOfMemory:
		return "out of memory"
	case StatusCancelledCommand:
		return "cancelled command"
	case StatusInvalidHandle:
		return "contextHandle does not exist"
	case StatusInvalidLocality:
		return "Hardware Locality does not exist"
	case StatusHandleDefined:
		return "handle already defined"
	case StatusArgumentNotSupported:
		return "argument is not supported by this profile, implementation, or integration"
	case StatusAlreadyInitialized:
		return "already initialized"
	case StatusInvalidParentLocality:
		return "Parent ContextHandle does not exist in the caller's locality"
	case StatusMaxTCIs:
		return "maximum number of TCIs have been created"
	case StatusPlatformError:
		return "error internal to platform"
	case StatusCryptoError:
		return "cryptography error"
	case StatusValidationError:
		return "validation error"
	default:
		return fmt.Sprintf("unrecognized status code 0x%0x", uint32(s))
	}
}
