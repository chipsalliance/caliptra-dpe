module github.com/chipsalliance/caliptra-dpe/verification/testing

go 1.24.0

toolchain go1.24.13

replace github.com/chipsalliance/caliptra-dpe/verification/client => ../client

replace github.com/chipsalliance/caliptra-dpe/verification/sim => ../sim

require (
	github.com/chipsalliance/caliptra-dpe/verification/client v0.0.0-20240305022518-f4e3dd792a5c
	github.com/chipsalliance/caliptra-dpe/verification/sim v0.0.0-20240305022518-f4e3dd792a5c
	github.com/cloudflare/circl v1.6.1
	github.com/github/smimesign v0.2.0
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.4.3
	github.com/zmap/zcrypto v0.0.0-20231219022726-a1f61fb1661c
	github.com/zmap/zlint/v3 v3.6.1
	golang.org/x/exp v0.0.0-20240222234643-814bf88cf225
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.11.0 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/weppos/publicsuffix-go v0.30.2-0.20230730094716-a20f9abcc222 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)
