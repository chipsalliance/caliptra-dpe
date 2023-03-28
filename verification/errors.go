package verification

import "fmt"

type Status uint32

const (
	StatusInternalError        Status = 1
	StatusInvalidCommand       Status = 2
	StatusInvalidArgument      Status = 3
	StatusArgumentNotSupported Status = 4
	StatusInvalidHandle        Status = 0x1000
	StatusInvalidLocality      Status = 0x1001
	StatusBadTag               Status = 0x1002
	StatusHandleDefined        Status = 0x1003
	StatusMaxTCIs              Status = 0x1004
)

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
	case StatusBadTag:
		return "TCI Tag is either in use (TagTci) or not found (GetTaggedTci)"
	case StatusHandleDefined:
		return "passed handle is already defined"
	case StatusMaxTCIs:
		return "maximum number of TCIs have been created"
	default:
		return fmt.Sprintf("unrecognized status code 0x%0x", uint32(s))
	}
}
