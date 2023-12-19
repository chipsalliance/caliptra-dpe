// Licensed under the Apache-2.0 license

package verification

import "fmt"

// Status is a DPE status code
type Status uint32

// All spec-defined DPE status codes
const (
	StatusInternalError        Status = 1
	StatusInvalidCommand       Status = 2
	StatusInvalidArgument      Status = 3
	StatusArgumentNotSupported Status = 4
	StatusInvalidHandle        Status = 0x1000
	StatusInvalidLocality      Status = 0x1001
	StatusBadTag               Status = 0x1002
	StatusMaxTCIs              Status = 0x1003
	StatusPlatformError        Status = 0x1004
	StatusCryptoError          Status = 0x1005
	StatusHashError            Status = 0x1006
	StatusRandError            Status = 0x1007
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
	case StatusArgumentNotSupported:
		return "argument is not supported by this profile, implementation, or integration"
	case StatusInvalidHandle:
		return "contextHandle does not exist"
	case StatusInvalidLocality:
		return "Hardware Locality does not exist"
	case StatusMaxTCIs:
		return "maximum number of TCIs have been created"
	case StatusPlatformError:
		return "error internal to platform"
	case StatusCryptoError:
		return "cryptography error"
	case StatusHashError:
		return "error in hashing buffer"
	case StatusRandError:
		return "error in random byte generation"
	default:
		return fmt.Sprintf("unrecognized status code 0x%0x", uint32(s))
	}
}
