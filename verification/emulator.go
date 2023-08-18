// Licensed under the Apache-2.0 license

package verification

const (
	emulatorSocketPath = "/tmp/dpe-emu.socket"

	DPE_EMULATOR_AUTO_INIT_LOCALITY    uint32  = 0
	DPE_EMULATOR_OTHER_LOCALITY        uint32  = 0x4f544852
	DPE_EMULATOR_PROFILE               Profile = ProfileP256SHA256
	DPE_EMULATOR_MAX_TCI_NODES         uint32  = 24
	DPE_EMULATOR_MAJOR_PROFILE_VERSION uint16  = CURRENT_PROFILE_MAJOR_VERSION
	DPE_EMULATOR_MINOR_PROFILE_VERSION uint16  = CURRENT_PROFILE_MINOR_VERSION
	DPE_EMULATOR_VENDOR_ID             uint32  = 0
	DPE_EMULATOR_VENDOR_SKU            uint32  = 0
)

//TODO code for emulator to start, stop, getsupport
