# DPE Simulator

The DPE simulator is a userspace simulator which serves as a DPE intance.

## Transport

The simulator exposes a bi-directional unix socket. Message formats are packed
binary structures as defined in the DPE library.

## Security

The simulator provides no security guarantees regarding the protection of
secrets. It should only be used for testing.
