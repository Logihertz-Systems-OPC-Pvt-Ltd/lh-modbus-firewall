# Contributing to Logihertz Modbus TCP Firewall (`lh-modbus-firewall`)

Thank you for your interest in contributing to `lh-modbus-firewall`, an industrial-grade Modbus TCP deep packet inspection firewall, MBAP/PDU dissector, setpoint guard, and OT/SCADA security posture auditor.

---

## Architectural & Governance Mandates

To ensure deterministic reliability, zero supply-chain exposure, and high performance in critical infrastructure:

1. **Zero External Go Dependencies**:
   - `go.mod` MUST remain 100% free of external third-party dependencies (`require` blocks).
   - All networking, cryptographic checksums, binary dissections, JSON handling, and SARIF generation must utilize Go standard library packages exclusively (`bytes`, `encoding/binary`, `encoding/hex`, `encoding/json`, `fmt`, `io`, `net`, `os`, `strconv`, `strings`, `sync`, `time`).
2. **Modbus Protocol Conformance**:
   - Dissections and validations must adhere strictly to the Modbus Application Protocol Specification V1.1b3 and Modbus Messaging on TCP/IP Implementation Guide V1.0b.
   - MBAP header Protocol ID must strictly be `0x0000`.
   - Modbus RTU CRC-16 must follow the standard reflected polynomial `0xA001` with `0xFFFF` seed.
   - Coil write operations (`0x05`) must validate that payloads are strictly `0x0000` (OFF) or `0xFF00` (ON).
3. **Deterministic Memory & Performance**:
   - Zero dynamic heap allocations in hot-path frame validation loops where practical.
   - Slew-rate rate limiting and stateful transaction maps must protect concurrent access with `sync.RWMutex` or atomic operations.
   - No panics or unhandled error states on malformed or fuzzing inputs.

---

## Development Workflow

### Prerequisites
- Go 1.22 or later.

### Building
```bash
go build -v -o bin/lh-modbus ./cmd/lh-modbus
```

### Formatting & Linting
All Go code must pass strict formatting and static analysis without warnings:
```bash
gofmt -s -l .
go vet ./...
```

### Running Test Suite
Unit, stateful, and CLI integration tests must run with race detection enabled:
```bash
go test -v -race ./...
```

---

## Pull Request Guidelines

1. **Focused Changes**: Submit atomic commits targeting specific features, bug fixes, or audit rules.
2. **Comprehensive Test Coverage**: Accompany every parser addition or firewall rule with unit tests covering valid, boundary, and maliciously malformed inputs.
3. **Zero Deprecation Warnings**: Code must compile cleanly under Go 1.22+.
4. **Licensing**: All contributions are licensed under the Apache License 2.0.
