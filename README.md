# Logihertz Modbus TCP Firewall (`lh-modbus-firewall`)

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-modbus-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-modbus-firewall/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-modbus-firewall)](https://goreportcard.com/report/github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-modbus-firewall)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-success.svg)](go.mod)

**`lh-modbus-firewall`** is a zero-dependency, industrial-grade **Modbus TCP Deep Packet Inspection (DPI) Firewall, MBAP/PDU Protocol Dissector, Physical Register Setpoint & Slew-Rate Guard, and 10-Rule OT/SCADA Security Posture Auditor** implemented in pure Go (1.22+ standard library).

Engineered by **Logihertz Systems (OPC) Private Limited** for critical infrastructure, industrial control systems (ICS), electrical substations, water treatment facilities, and sovereign edge appliances.

---

## Key Capabilities

- **Zero External Dependencies**: 100% Go standard library. Zero `require` blocks in `go.mod`. Eliminates supply-chain vulnerabilities in OT demilitarized zones (DMZ).
- **MBAP & PDU Deep Packet Inspection**:
  - Full dissection of 7-byte Modbus Application Protocol (MBAP) header: Transaction ID, Protocol ID (`0x0000`), Length ($2 \le \text{Length} \le 254$), and Unit ID (`0x00`..`0xFF`).
  - Wire length invariant enforcement: $L_{\text{wire}} = 6 + \text{Length}$.
  - Strict protocol validation rejecting malformed coil values (validates strictly `0x0000` [OFF] or `0xFF00` [ON]), non-zero protocol IDs, and invalid byte counts.
- **OT Threat Interception & Anti-Exploit**:
  - Intercepts Schneider Electric UMAS (`0x5A`) proprietary control codes to mitigate unauthenticated PLC stop and firmware manipulation (CVE-2019-10953).
  - Drops diagnostic function code `0x08` (Sub-functions `0x0001` restart comms, `0x0004` force listen only) and device identification (`0x2B`).
  - Prohibits broadcast writes to Unit ID `0x00`.
- **Physical Register Setpoint & Slew-Rate Protection**:
  - Enforces register-specific minimum/maximum value limits: $V_{\min}(r) \le V(r) \le V_{\max}(r)$.
  - Restricts maximum step changes ($\Delta V_{\max}$) to prevent sudden actuator shock, water hammer, or pressure surges: $|V(r) - V_{\text{prev}}(r)| \le \Delta V_{\max}(r)$.
  - Protects telemetry-only registers against write tampering (`read_only: true`).
- **Stateful Transaction Correlation**:
  - Tracks in-flight request Transaction IDs and Unit IDs to intercept unsolicited response injection, replay attacks, and transaction desynchronization.
- **Traffic Shaping & Token-Bucket Rate Limiting**:
  - Per-client and aggregate token-bucket rate limiter defending field serial gateways and low-power RTU microcontrollers from packet exhaustion.
- **10-Rule Industrial Posture Auditor**:
  - Deterministic audit scoring ($S \in [0, 100]$) mapping industrial misconfigurations directly to MITRE ATT&CK for ICS and CWE standards.
  - Multi-format reporting: Colorized ANSI terminal tables, Canonical JSON, and OASIS SARIF v2.1.0 for OT SIEM integration.
- **Modbus RTU CRC-16 Calculation**:
  - Hardware-aligned bit-level CRC-16 computation ($x^{16} + x^{15} + x^2 + 1$, reflected polynomial `0xA001`, initial `0xFFFF`).

---

## Architectural Overview

```
                          INDUSTRIAL NETWORK (PURDUE MODEL LEVEL 2/3)
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
         SCADA Master / HMI                          Untrusted / Rogue Node
          (192.168.10.15)                                 (10.0.0.99)
                  │                                               │
                  │ [Port 502 / TCP]                              │ [Injected Writes]
                  └───────────────────────┬───────────────────────┘
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │          lh-modbus-firewall           │
                      │  Industrial Deep Packet Inspection    │
                      ├───────────────────────────────────────┤
                      │ 1. Token-Bucket Polling Rate Limiter  │
                      │    N(t) = min(B, N(t_k) + r Δt)       │
                      ├───────────────────────────────────────┤
                      │ 2. MBAP Header & Wire Invariant Check │
                      │    L_wire == 6 + MBAP.Length          │
                      │    MBAP.ProtocolID == 0x0000          │
                      ├───────────────────────────────────────┤
                      │ 3. Client IP & Write Permission Check │
                      │    AllowedWriteClientIPs whitelist    │
                      ├───────────────────────────────────────┤
                      │ 4. Function Code Filter               │
                      │    Block 0x08, 0x2B, 0x5A (UMAS)      │
                      ├───────────────────────────────────────┤
                      │ 5. Physical Setpoint Envelope Guard   │
                      │    V_min(r) <= V(r) <= V_max(r)       │
                      ├───────────────────────────────────────┤
                      │ 6. Slew-Rate Step-Change Limiter      │
                      │    |V(r) - V_prev(r)| <= ΔV_max(r)    │
                      ├───────────────────────────────────────┤
                      │ 7. Stateful Transaction Correlation   │
                      │    PendingTx[(UnitID, TxID)]          │
                      └───────────────────┬───────────────────┘
                                          │ (Filtered & Validated Traffic)
                                          ▼
                      ┌───────────────────────────────────────┐
                      │          Field PLC / RTU              │
                      │   Downstream Actuators & Sensors      │
                      └───────────────────────────────────────┘
```

---

## Mathematical Formulations

### 1. MBAP Header Wire Alignment
In Modbus TCP, the 7-byte MBAP header defines:
$$\text{MBAP} = \{\text{TransactionID}_{16}, \text{ProtocolID}_{16}, \text{Length}_{16}, \text{UnitID}_{8}\}$$
where $\text{Length}$ represents the number of following bytes (1 byte Unit ID plus $N$ bytes PDU). The firewall validates the physical wire invariant:
$$L_{\text{wire}} = 6 + \text{Length} \quad \text{where } 2 \le \text{Length} \le 254 \land \text{ProtocolID} = 0x0000$$

### 2. Modbus RTU Reflected CRC-16
Modbus RTU frames employ a 16-bit cyclic redundancy check with polynomial:
$$P(x) = x^{16} + x^{15} + x^2 + 1 \implies \text{Reflected Mask: } \mathtt{0xA001}$$
Starting from initial seed $\mathtt{0xFFFF}$, each byte is XORed into the lower 8 bits of the shift register. If the least significant bit is 1, the register is shifted right and XORed with $\mathtt{0xA001}$; otherwise, it is shifted right. Transmitted on wire in Little-Endian format (low byte first).

### 3. Physical Setpoint Envelope & Slew-Rate Guard
For any write operation targeting register address $r$:
$$V_{\min}(r) \le V_{\text{target}}(r) \le V_{\max}(r)$$
$$|V_{\text{target}}(r) - V_{\text{prev}}(r)| \le \Delta V_{\max}(r)$$
If either inequality is violated, the frame is dropped immediately, preventing mechanical valve overtravel, cavitation, or frequency jumps.

### 4. Token-Bucket Rate Limiting
Traffic for client $c$ is governed by replenishment rate $r_{\text{pps}}$ and burst capacity $B$:
$$N_{\text{tokens}}(t) = \min\left(B, \; N_{\text{tokens}}(t_{k-1}) + r_{\text{pps}} \cdot (t - t_{k-1})\right)$$
Frames requiring $> N_{\text{tokens}}(t)$ are dropped with `LH-MODBUS-007`.

---

## 10-Rule OT/SCADA Security Posture Matrix

The firewall auditor evaluates policies against 10 deterministic security rules. The overall posture score is calculated via:
$$S = \max\left(0, \; 100 - \sum_{i=1}^{10} W_i \cdot \mathbb{I}(\text{Rule } i \text{ Failed})\right)$$

| Rule ID | Severity | Weight | CWE | Title | Enforcement Target |
|---|---|---|---|---|---|
| **`LH-MODBUS-001`** | **CRITICAL** | 25 | CWE-306 | Unrestricted Modbus Write Function Codes Allowed | Drops writes from non-whitelisted client IPs |
| **`LH-MODBUS-002`** | **CRITICAL** | 25 | CWE-284 | Diagnostic or Proprietary PLC Function Codes Permitted | Blocks FC 0x08, 0x2B, 0x5A (Schneider UMAS) |
| **`LH-MODBUS-003`** | **CRITICAL** | 25 | CWE-319 | Plaintext Modbus Port 502 Exposed Across Untrusted Boundary | Enforces Port 802 TLS or VPN encapsulation |
| **`LH-MODBUS-004`** | **HIGH** | 10 | CWE-20 | Missing Strict MBAP Header and PDU Protocol Validation | Rejects length mismatches and malformed coils |
| **`LH-MODBUS-005`** | **HIGH** | 10 | CWE-285 | Unbounded Register Address Ranges or Unconstrained Setpoints | Enforces min/max value envelopes & read-only tags |
| **`LH-MODBUS-006`** | **HIGH** | 10 | CWE-290 | Permissive Unit ID Zero Broadcast or Gateway Routing Allowed | Blocks Unit ID 0 and enforces slave allowlists |
| **`LH-MODBUS-007`** | **HIGH** | 10 | CWE-400 | Excessive Polling Frequency or Unbounded Concurrent TCP Sessions | Enforces rate limit ($\le 200$ pps) & session clamp |
| **`LH-MODBUS-008`** | **MEDIUM** | 4 | CWE-345 | Stateless Transaction Tracking (Missing Transaction ID Correlation) | Pairs request/response Transaction IDs |
| **`LH-MODBUS-009`** | **MEDIUM** | 4 | CWE-693 | Missing Physical Slew-Rate / Sudden Step-Change Limiter | Restricts maximum step changes ($\Delta V_{\max}$) |
| **`LH-MODBUS-010`** | **LOW** | 1 | CWE-778 | Modbus Exception Code Scanning and OT SIEM Telemetry Disabled | Logs exception code anomalies to industrial SIEM |

### Posture Status Tiers
- **`100 / 100`**: `HARDENED` — Zero defects detected. Compliant with industrial cybersecurity standards.
- **`85 .. 99`**: `ADEQUATE` — Minor posture deficiencies. Acceptable for isolated air-gapped segments.
- **`60 .. 84`**: `ELEVATED_RISK` — Substantial vulnerabilities present. High risk of setpoint tampering.
- **`< 60`**: `CRITICAL_RISK` — Immediate exposure to unauthenticated command injection or PLC manipulation.

---

## Installation & Build

### Prerequisites
- Go 1.22 or higher.

### Compilation
```bash
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-modbus-firewall.git
cd lh-modbus-firewall
go build -v -ldflags="-s -w" -o bin/lh-modbus ./cmd/lh-modbus
```

---

## Command-Line Interface (CLI)

```
lh-modbus v0.1.0 - Industrial Modbus TCP DPI Firewall & Security Posture Auditor
Author: Sameer Tawade | Logihertz Systems (OPC) Private Limited (https://logihertz.com/)

USAGE:
  lh-modbus <command> [arguments...]

COMMANDS:
  scan          Audit firewall policy against 10 OT/SCADA security posture rules
  inspect-frame Deep packet inspection of a raw Modbus TCP or RTU hex frame
  filter-trace  Simulate and evaluate a series of Modbus frames against firewall policy
  crc16         Compute standard Modbus RTU CRC-16 checksum for raw hex data
  version       Print tool version and copyright information
  help          Display this help message
```

### 1. Audit Policy Posture (`scan`)
```bash
# Terminal table output
./bin/lh-modbus scan fixtures/hardened_modbus_policy.json

# Machine-readable JSON output
./bin/lh-modbus scan --format=json fixtures/hardened_modbus_policy.json

# OASIS SARIF v2.1.0 export for CI/CD or SIEM ingestion
./bin/lh-modbus scan --format=sarif --output=audit.sarif fixtures/vulnerable_modbus_policy.json
```

### 2. Deep Packet Inspection (`inspect-frame`)
```bash
# Inspect a Modbus TCP frame (Read Holding Registers, Start 100, Qty 10)
./bin/lh-modbus inspect-frame 00010000000601030064000A

# Inspect a Modbus RTU serial frame with verified CRC-16
./bin/lh-modbus inspect-frame 01030000000AC5CD

# Inspect an anomalous frame (Schneider UMAS 0x5A)
./bin/lh-modbus inspect-frame 000400000003015A01
```

### 3. Packet Trace Simulation (`filter-trace`)
```bash
# Evaluate network trace against hardened firewall policy
./bin/lh-modbus filter-trace fixtures/hardened_modbus_policy.json fixtures/sample_modbus_trace.json
```

### 4. Modbus RTU CRC-16 Checksum (`crc16`)
```bash
./bin/lh-modbus crc16 01030000000A
# Output:
# Input Hex : 01030000000A (6 bytes)
# CRC-16    : 0xCDC5
# Wire Bytes: C5 CD (Little-Endian: Low Byte 0xC5, High Byte 0xCD)
```

---

## Exit Codes

| Exit Code | Classification | Description |
|---|---|---|
| `0` | **COMPLIANT / CLEAN** | Audit score 100/100, zero frame anomalies detected, or all trace packets accepted. |
| `1` | **SECURITY FINDING / DROP** | Posture score $< 100$, packet frame dropped by firewall, or protocol anomaly detected. |
| `2` | **USAGE / SYSTEM ERROR** | Missing CLI arguments, invalid hex encoding, or file I/O error. |

---

## Policy Schema Example

```json
{
  "name": "Hardened Substation OT Modbus Security Policy",
  "allow_unrestricted_writes": false,
  "allowed_write_client_ips": ["192.168.10.15", "192.168.10.20"],
  "block_diagnostic_and_proprietary_fcs": true,
  "wan_port_502_exposed": false,
  "require_tls_802_or_tunnel": true,
  "strict_mbap_pdu_validation": true,
  "enforce_register_address_bounds": true,
  "enforce_setpoint_value_limits": true,
  "block_unit_id_zero_broadcast": true,
  "unit_id_allowlist_enabled": true,
  "allowed_unit_ids": [1, 2, 3],
  "rate_limiting_enabled": true,
  "max_requests_per_sec": 100,
  "max_concurrent_tcp_sessions": 8,
  "stateful_transaction_tracking": true,
  "register_slew_rate_guard": true,
  "log_exception_scans": true,
  "ot_siem_audit_logging": true,
  "allowed_function_codes": [1, 2, 3, 4, 5, 6, 15, 16],
  "register_rules": [
    {
      "address": 100,
      "name": "Coolant Pump VFD Speed (RPM)",
      "read_only": false,
      "min_value": 100,
      "max_value": 1800,
      "max_slew_rate": 200
    },
    {
      "address": 102,
      "name": "Generator Turbine Speed Telemetry",
      "read_only": true
    }
  ]
}
```

---

## License & Attribution

Licensed under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for details.

Developed by **Sameer Tawade**, Creator, Founder, Director & Sole Developer at **Logihertz Systems (OPC) Private Limited** (<https://logihertz.com/>).
