# Changelog

All notable changes to `lh-modbus-firewall` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-13

### Added
- **MBAP / PDU Dissection Engine**:
  - Full dissection of 7-byte Modbus Application Protocol (MBAP) header: Transaction ID, Protocol ID (`0x0000`), Length ($2 \le L \le 254$), and Unit ID (`0x00`..`0xFF`).
  - Strict length verification checking wire length match ($L_{\text{wire}} = 6 + \text{Length}$).
  - PDU dissection for standard read functions: `0x01` (Coils), `0x02` (Discrete Inputs), `0x03` (Holding Registers), `0x04` (Input Registers).
  - PDU dissection for write functions: `0x05` (Single Coil, validating `0x0000`/`0xFF00`), `0x06` (Single Register), `0x0F` (Multiple Coils), `0x10` (Multiple Registers), `0x16` (Mask Write Register), `0x17` (Read/Write Multiple Registers).
  - Diagnostic function code dissection: `0x08` with sub-function decoding (`0x0000` Echo, `0x0001` Restart Comms, `0x0004` Force Listen Only).
  - Detection and interception of proprietary PLC control codes, including Schneider Electric UMAS (`0x5A`) and user-defined function code ranges (`65..72`, `100..110`).
  - Standard Modbus RTU CRC-16 computation using reflected polynomial `0xA001` and `0xFFFF` seed.
- **Deep Packet Inspection Firewall & Guard**:
  - Stateful transaction correlation tracking Transaction ID and Unit ID to prevent desynchronization and unsolicited frame injection.
  - Granular client IP allowlist enforcement distinguishing read and write permissions.
  - Physical register setpoint envelope validation enforcing register-specific minimum and maximum value bounds.
  - Slew-rate limiter ($\Delta V_{\max}$) preventing abrupt setpoint steps and mechanical stress on physical actuators.
  - Token-bucket rate limiter defending against packet flood attacks and polling starvation.
  - Unit ID 0 broadcast write prevention.
- **10-Rule Industrial Posture Auditor**:
  - `LH-MODBUS-001`: Unrestricted Modbus Write Function Codes Allowed (Critical, 25 pts, CWE-306).
  - `LH-MODBUS-002`: Diagnostic or Proprietary PLC Function Codes Permitted (Critical, 25 pts, CWE-284).
  - `LH-MODBUS-003`: Plaintext Modbus Port 502 Exposed Across Untrusted Boundary (Critical, 25 pts, CWE-319).
  - `LH-MODBUS-004`: Missing Strict MBAP Header and PDU Protocol Validation (High, 10 pts, CWE-20).
  - `LH-MODBUS-005`: Unbounded Register Address Ranges or Unconstrained Setpoints (High, 10 pts, CWE-285).
  - `LH-MODBUS-006`: Permissive Unit ID Zero Broadcast or Gateway Routing Allowed (High, 10 pts, CWE-290).
  - `LH-MODBUS-007`: Excessive Polling Frequency or Unbounded Concurrent TCP Sessions (High, 10 pts, CWE-400).
  - `LH-MODBUS-008`: Stateless Transaction Tracking (Missing MBAP Transaction ID Correlation) (Medium, 4 pts, CWE-345).
  - `LH-MODBUS-009`: Missing Physical Slew-Rate / Sudden Step-Change Limiter (Medium, 4 pts, CWE-693).
  - `LH-MODBUS-010`: Modbus Exception Code Scanning and OT SIEM Telemetry Disabled (Low, 1 pt, CWE-778).
- **Multi-Format Reporting & CLI**:
  - Rich ANSI colorized terminal tables for posture audits and packet inspection.
  - Canonical deterministic JSON exporter.
  - OASIS SARIF v2.1.0 exporter for industrial DevSecOps and OT SIEM integration.
  - CLI commands: `scan`, `inspect-frame`, `filter-trace`, `crc16`, `--version`, `--help`.
- **Zero-Dependency Architecture**:
  - Built entirely on Go 1.22+ standard library with zero external runtime or build dependencies.
