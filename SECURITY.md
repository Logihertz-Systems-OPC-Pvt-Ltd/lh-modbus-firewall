# Security Policy

## Supported Versions

Logihertz Systems (OPC) Private Limited maintains security updates and patch releases for the following versions of `lh-modbus-firewall`:

| Version | Supported          | Security Maintenance Status |
|---------|--------------------|-----------------------------|
| 0.1.x   | :white_check_mark: | Active Current Release      |
| < 0.1.0 | :x:                | Unsupported Initial Dev     |

---

## Threat Model & Security Posture

Industrial Modbus TCP (IEC 61158 / IEC 62443) networks operate under unique constraints:
- **Zero In-Band Authentication or Encryption**: Standard Modbus TCP (port 502) transmits plain text MBAP headers and PDU payloads without authentication, integrity checks, or encryption.
- **Unauthorized Setpoint Tampering**: Malicious or unauthorized write commands (`0x05`, `0x06`, `0x0F`, `0x10`) can push physical actuator setpoints beyond safe mechanical thresholds or trigger rapid oscillations.
- **Proprietary & Diagnostic Exploits**: Vendor-specific function codes (such as Schneider Electric UMAS `0x5A`, CVE-2019-10953) allow attackers to halt programmable logic controllers (PLCs), dump firmware memory, or overwrite ladder logic without authentication.
- **Denial of Service (DoS)**: High-frequency polling loops, connection exhaustion, and broadcast writes (Unit ID `0x00`) can freeze embedded field gateway serial loops and degrade deterministic RTU polling.

`lh-modbus-firewall` addresses these industrial threats through:
1. **Deterministic MBAP Header Validation**: Validates protocol identifier (`0x0000`), bounded length fields ($2 \le \text{Length} \le 254$), and wire length alignment ($L_{\text{wire}} = 6 + \text{Length}$).
2. **Function Code Filtering**: Granular function code whitelists blocking diagnostic (`0x08`), device identification (`0x2B`), UMAS (`0x5A`), and unapproved write operations.
3. **Physical Setpoint & Slew-Rate Guards**: Strict upper/lower value boundaries and per-interval maximum slew-rate limits ($\Delta V_{\max}$) preventing mechanical shock to field devices.
4. **Token-Bucket Rate Limiting**: Per-client and aggregate token-bucket traffic shaping preventing SCADA master CPU starvation and packet floods.
5. **Stateful Transaction Correlation**: Request-response pairing tracking Transaction ID and Unit ID to block unsolicited responses and replay injection.

---

## Reporting a Vulnerability

We take the security of industrial automation and edge infrastructure seriously. If you discover a security vulnerability in `lh-modbus-firewall`, please report it responsibly:

- **Primary Contact**: Sameer Tawade <ops@logihertz.com>
- **Subject Header**: `[SECURITY VULNERABILITY] lh-modbus-firewall - <Short Description>`
- **Response Timeline**: Acknowledgement within 24 hours, triage and preliminary assessment within 48 hours.
- **Coordinated Disclosure**: We adhere to coordinated vulnerability disclosure. Please allow up to 14 business days for patch engineering and verification before public disclosure.

Please include:
- Reproducible proof-of-concept (pcap, hex payload trace, or policy file)
- Affected firewall component or rule ID
- Impact assessment on OT/SCADA operations
