module github.com/chipsalliance/caliptra-dpe/verification/testing

go 1.20

replace github.com/chipsalliance/caliptra-dpe/verification/client => ../client

require (
	github.com/chipsalliance/caliptra-dpe/verification/client v0.0.0-00010101000000-000000000000
	github.com/github/smimesign v0.2.0
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.4.1
	github.com/zmap/zcrypto v0.0.0-20230422215203-9a665e1e9968
	github.com/zmap/zlint/v3 v3.4.1
	golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63
)

require (
	github.com/google/go-sev-guest v0.7.0 // indirect
	github.com/google/go-tdx-guest v0.2.1-0.20230907045450-944015509c84 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pelletier/go-toml v1.9.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/weppos/publicsuffix-go v0.30.1-0.20230422193905-8fecedd899db // indirect
	golang.org/x/crypto v0.11.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/text v0.11.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)
