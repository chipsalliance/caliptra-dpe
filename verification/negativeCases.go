// Licensed under the Apache-2.0 license

package verification

import (
	"errors"
	"testing"
)

// InvalidHandle is a sample DPE handle which is very unlikely to be valid
var InvalidHandle = ContextHandle{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// TestInvalidHandle checks whether error is reported when non-existent handle
// is passed as input to DPE commands.
// Exceptions are - GetProfile, InitializeContext, GetCertificateChain, commands
// which do not need context handle as input parameter.
func TestInvalidHandle(d TestDPEInstance, c DPEClient, t *testing.T) {
	ctx := getInitialContextHandle(d, c, t, true)
	defer c.DestroyContext(ctx, DestroyDescendants)

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	// Check DeriveChild with invalid handle
	if _, err := c.DeriveChild(&InvalidHandle, make([]byte, digestLen), 0, 0, 0); err == nil {
		t.Errorf("[ERROR]: DeriveChild should return %q, but returned no error", StatusInvalidHandle)
	} else if !errors.Is(err, StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. DeriveChild should return %q, but returned %q", StatusInvalidHandle, err)
	}

	// Check CertifyKey with invalid handle
	if _, err := c.CertifyKey(&InvalidHandle, make([]byte, digestLen), 0, 0); err == nil {
		t.Errorf("[ERROR]: CertifyKey should return %q, but returned no error", StatusInvalidHandle)
	} else if !errors.Is(err, StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. CertifyKey should return %q, but returned %q", StatusInvalidHandle, err)
	}

	// Check Sign with invalid handle
	if _, err := c.Sign(&InvalidHandle, make([]byte, digestLen), 0, make([]byte, digestLen)); err == nil {
		t.Errorf("[ERROR]: Sign should return %q, but returned no error", StatusInvalidHandle)
	} else if !errors.Is(err, StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. Sign should return %q, but returned %q", StatusInvalidHandle, err)
	}

	// Check RotateContextHandle with invalid handle
	if _, err := c.RotateContextHandle(&InvalidHandle, RotateContextHandleFlags(TargetIsDefault)); err == nil {
		t.Errorf("[ERROR]: RotateContextHandle should return %q, but returned no error", StatusInvalidHandle)
	} else if !errors.Is(err, StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. RotateContextHandle should return %q, but returned %q", StatusInvalidHandle, err)
	}

	// Check DestroyContext with invalid handle
	if err := c.DestroyContext(&InvalidHandle, 0); err == nil {
		t.Errorf("[ERROR]: DestroyContext should return %q, but returned no error", StatusInvalidHandle)
	} else if !errors.Is(err, StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. DestroyContext should return %q, but returned %q", StatusInvalidHandle, err)
	}

	// Check ExtendTCI with invalid handle
	if _, err := c.ExtendTCI(&InvalidHandle, make([]byte, digestLen)); err == nil {
		t.Errorf("[ERROR]: ExtendTCI should return %q, but returned no error", StatusInvalidHandle)
	} else if !errors.Is(err, StatusInvalidHandle) {
		t.Errorf("[ERROR]: Incorrect error type. ExtendTCI should return %q, but returned %q", StatusInvalidHandle, err)
	}
}

// TestWrongLocality checks whether error is reported when caller from one
// locality issues DPE commands in another locality.
// Exceptions are - GetProfile, InitializeContext, GetCertificateChain, commands
// which do not need context handle as input and hence locality is irrelevant.
func TestWrongLocality(d TestDPEInstance, c DPEClient, t *testing.T) {
	if !d.HasLocalityControl() {
		t.Skipf("Target does not have locality control")
	}

	// Modify and later restore the locality of DPE instance to test
	currentLocality := d.GetLocality()
	d.SetLocality(currentLocality + 1)
	defer d.SetLocality(currentLocality)

	// Get default context handle
	handle := &DefaultContextHandle

	// Get digest size
	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}

	digestLen := profile.GetDigestSize()

	// Check DeriveChild from wrong context
	if _, err := c.DeriveChild(handle, make([]byte, digestLen), 0, 0, 0); err == nil {
		t.Errorf("[ERROR]: DeriveChild should return %q, but returned no error", StatusInvalidLocality)
	} else if !errors.Is(err, StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. DeriveChild should return %q, but returned %q", StatusInvalidLocality, err)
	}

	// Check CertifyKey from wrong locality
	if _, err := c.CertifyKey(handle, make([]byte, digestLen), 0, 0); err == nil {
		t.Errorf("[ERROR]: CertifyKey should return %q, but returned no error", StatusInvalidLocality)
	} else if !errors.Is(err, StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. CertifyKey should return %q, but returned %q", StatusInvalidLocality, err)
	}

	// Check Sign from wrong locality
	if _, err := c.Sign(handle, make([]byte, digestLen), 0, make([]byte, digestLen)); err == nil {
		t.Errorf("[ERROR]: Sign should return %q, but returned no error", StatusInvalidLocality)
	} else if !errors.Is(err, StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. Sign should return %q, but returned %q", StatusInvalidLocality, err)
	}

	// Check RotateContextHandle from wrong locality
	if _, err := c.RotateContextHandle(handle, RotateContextHandleFlags(TargetIsDefault)); err == nil {
		t.Errorf("[ERROR]: RotateContextHandle should return %q, but returned no error", StatusInvalidLocality)
	} else if !errors.Is(err, StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. RotateContextHandle should return %q, but returned %q", StatusInvalidLocality, err)
	}

	// Check DestroyContext from wrong locality
	if err := c.DestroyContext(handle, 0); err == nil {
		t.Errorf("[ERROR]: DestroyContext should return %q, but returned no error", StatusInvalidLocality)
	} else if !errors.Is(err, StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. DestroyContext should return %q, but returned %q", StatusInvalidLocality, err)
	}

	// Check ExtendTCI from wrong locality
	if _, err := c.ExtendTCI(handle, make([]byte, digestLen)); err == nil {
		t.Errorf("[ERROR]: ExtendTCI should return %q, but returned no error", StatusInvalidLocality)
	} else if !errors.Is(err, StatusInvalidLocality) {
		t.Errorf("[ERROR]: Incorrect error type. ExtendTCI should return %q, but returned %q", StatusInvalidLocality, err)
	}
}

// TestUnsupportedCommand checks whether error is reported while using commands
// that are turned off in DPE.
// DPE commands - RotateContextHandle, ExtendTCI, require support to be enabled in DPE profile
// before being called.
func TestUnsupportedCommand(d TestDPEInstance, c DPEClient, t *testing.T) {
	ctx := &DefaultContextHandle

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	// Check whether RotateContextHandle is unsupported by DPE profile
	if _, err := c.RotateContextHandle(ctx, RotateContextHandleFlags(TargetIsDefault)); err == nil {
		t.Errorf("[ERROR]: RotateContextHandle is not supported by DPE, should return %q, but returned no error", StatusInvalidCommand)
	} else if !errors.Is(err, StatusInvalidCommand) {
		t.Errorf("[ERROR]: Incorrect error type. RotateContextHandle is not supported by DPE, should return %q, but returned %q", StatusInvalidCommand, err)
	}

	// Check whether ExtendTCI is unsupported by DPE profile
	if _, err := c.ExtendTCI(ctx, make([]byte, digestLen)); err == nil {
		t.Errorf("[ERROR]: ExtendTCI is not supported by DPE, should return %q, but returned no error", StatusInvalidCommand)
	} else if !errors.Is(err, StatusInvalidCommand) {
		t.Errorf("[ERROR]: Incorrect error type. ExtendTCI is not supported by DPE, should return %q, but returned %q", StatusInvalidCommand, err)
	}
}

// TestUnsupportedCommandFlag checks whether error is reported while enabling
// command flags that are turned off in DPE.
// The DPE command may be available but some of its flags may not be supported by DPE.
// DPE profile supports the below attributes.
// Simulation	: Allows caller to request for context initialization in simulation mode
// IsCA			: Allows caller to request the key cert of CA
// Csr 			: Allows caller to request the key cert in CSR format
// X509 		: Allows caller to request the key cert in X509 format
// IsSymmetric 	: Allows caller to request for symmetric signing
// InternalInfo	: Allows caller to derive child context with InternalInfo
// InternalDice	: Allows caller to derive child context with InternalDice
func TestUnsupportedCommandFlag(d TestDPEInstance, c DPEClient, t *testing.T) {
	handle := &DefaultContextHandle

	profile, err := GetTransportProfile(d)
	if err != nil {
		t.Fatalf("Could not get profile: %v", err)
	}
	digestLen := profile.GetDigestSize()

	// Check whether error is returned since simulation context initialization is unsupported by DPE profile
	if _, err := c.InitializeContext(InitIsSimulation); err == nil {
		t.Errorf("[ERROR]: Simulation is not supported by DPE, InitializeContext should return %q, but returned no error", StatusArgumentNotSupported)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. Simulation is not supported by DPE, InitializeContext supported by DPE, should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since CA certificate request is unsupported by DPE profile
	if _, err := c.CertifyKey(handle, make([]byte, digestLen), CertifyKeyX509, CertifyAddIsCA); err == nil {
		t.Errorf("[ERROR]: IS_CA is not supported by DPE, CertifyKey should return %q, but returned no error", StatusArgumentNotSupported)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. IS_CA is not supported by DPE, CertifyKey should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since CSR format is unsupported by DPE profile
	if _, err := c.CertifyKey(handle, make([]byte, digestLen), CertifyKeyCsr, 0); err == nil {
		t.Errorf("[ERROR]: CSR format is not supported by DPE, CertifyKey should return %q, but returned no error", StatusArgumentNotSupported)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. CSR format is not supported by DPE, CertifyKey should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since X509 format is unsupported by DPE profile
	if _, err := c.CertifyKey(handle, make([]byte, digestLen), CertifyKeyX509, 0); err == nil {
		t.Errorf("[ERROR]: X509 format is not supported by DPE, CertifyKey should return %q, but returned no error", StatusArgumentNotSupported)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. X509 format is not supported by DPE, CertifyKey should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since symmetric signing is unsupported by DPE profile
	if _, err := c.Sign(handle, make([]byte, digestLen), SignFlags(IsSymmetric), make([]byte, digestLen)); err == nil {
		t.Errorf("[ERROR]: Symmetric signing is not supported by DPE, Sign should return %q, but returned no error", StatusInvalidArgument)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type.  Symmetric signing is not supported by DPE, Sign should return %q, but returned %q", StatusInvalidArgument, err)
	}

	// Check whether error is returned since InternalInfo usage is unsupported by DPE profile
	if _, err := c.DeriveChild(handle, make([]byte, digestLen), DeriveChildFlags(InternalInputInfo), 0, 0); err == nil {
		t.Errorf("[ERROR]:InternalInfo is not supported by DPE, DeriveChild should return %q, but returned no error", StatusArgumentNotSupported)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. InternalInfo is not supported by DPE, DeriveChild should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since InternalDice usgae is unsupported by DPE profile
	if _, err := c.DeriveChild(handle, make([]byte, digestLen), DeriveChildFlags(InternalInputDice), 0, 0); err == nil {
		t.Errorf("[ERROR]:InternalDice is not supported by DPE, DeriveChild should return %q, but returned no error", StatusArgumentNotSupported)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. InternalDice is not supported by DPE, DeriveChild should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since InternalInfo usage is unsupported by DPE profile
	if _, err := c.DeriveChild(handle, make([]byte, digestLen), DeriveChildFlags(InputAllowCA), 0, 0); err == nil {
		t.Errorf("[ERROR]:IS_CA is not supported by DPE, DeriveChild should return %q, but returned no error", StatusArgumentNotSupported)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. IS_CA is not supported by DPE, DeriveChild should return %q, but returned %q", StatusArgumentNotSupported, err)
	}

	// Check whether error is returned since InternalDice usgae is unsupported by DPE profile
	if _, err := c.DeriveChild(handle, make([]byte, digestLen), DeriveChildFlags(InputAllowX509), 0, 0); err == nil {
		t.Errorf("[ERROR]:X509 is not supported by DPE, DeriveChild should return %q, but returned no error", StatusArgumentNotSupported)
	} else if !errors.Is(err, StatusArgumentNotSupported) {
		t.Errorf("[ERROR]: Incorrect error type. X509 is not supported by DPE, DeriveChild should return %q, but returned %q", StatusArgumentNotSupported, err)
	}
}
