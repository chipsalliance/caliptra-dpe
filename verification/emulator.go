// Licensed under the Apache-2.0 license

package verification

// Added the dummy path and flags
const (
	emulatorSocketPath = "/tmp/dpe-emu.socket"

	DPE_EMULATOR_AUTO_INIT_LOCALITY    uint32  = 0
	DPE_EMULATOR_OTHER_LOCALITY        uint32  = 0
	DPE_EMULATOR_PROFILE               Profile = 0
	DPE_EMULATOR_MAX_TCI_NODES         uint32  = 0
	DPE_EMULATOR_MAJOR_PROFILE_VERSION uint16  = 0
	DPE_EMULATOR_MINOR_PROFILE_VERSION uint16  = 0
	DPE_EMULATOR_VENDOR_ID             uint32  = 0
	DPE_EMULATOR_VENDOR_SKU            uint32  = 0
)

//TODO code for emulator to start, stop, getsupport
