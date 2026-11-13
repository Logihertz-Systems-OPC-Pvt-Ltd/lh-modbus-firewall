package modbus

import (
	"time"
)

// AuditPolicy evaluates a FirewallPolicy against the 10 Logihertz OT/SCADA security posture rules.
func AuditPolicy(policy *FirewallPolicy) *AuditReport {
	report := &AuditReport{
		PolicyName: policy.Name,
		TotalRules: 10,
		Findings:   make([]AuditFinding, 0),
		AuditedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	deductions := 0

	// Rule 1: LH-MODBUS-001 (CRITICAL, 25 pts, CWE-306)
	if policy.AllowUnrestrictedWrites || len(policy.AllowedWriteClientIPs) == 0 {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-001",
			Title:       "Unrestricted Modbus Write Function Codes Allowed",
			Severity:    SeverityCritical,
			Weight:      25,
			CWE:         "CWE-306: Missing Authentication for Critical Function",
			Description: "Write function codes (0x05, 0x06, 0x0F, 0x10) are permitted without client IP restriction. Any device on the subnet can issue unauthorized actuator and setpoint commands.",
			Remediation: "Set 'allow_unrestricted_writes: false' and restrict 'allowed_write_client_ips' strictly to authorized Engineering Workstations (EWS) or SCADA master nodes.",
		})
		deductions += 25
	}

	// Rule 2: LH-MODBUS-002 (CRITICAL, 25 pts, CWE-284)
	if !policy.BlockDiagnosticAndProprietaryFCs {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-002",
			Title:       "Diagnostic or Proprietary PLC Function Codes Permitted",
			Severity:    SeverityCritical,
			Weight:      25,
			CWE:         "CWE-284: Improper Access Control",
			Description: "Diagnostic function codes (0x08) or proprietary PLC control codes (such as Schneider Electric UMAS 0x5A) are not blocked, allowing remote PLC restart, firmware memory extraction, or unauthorized ladder logic upload (CVE-2019-10953).",
			Remediation: "Enable 'block_diagnostic_and_proprietary_fcs: true' to intercept and drop FC 0x08, 0x2B, 0x5A, and user-defined vendor ranges.",
		})
		deductions += 25
	}

	// Rule 3: LH-MODBUS-003 (CRITICAL, 25 pts, CWE-319)
	if policy.WanPort502Exposed || !policy.RequireTLS802OrTunnel {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-003",
			Title:       "Plaintext Modbus Port 502 Exposed Across Untrusted Boundary",
			Severity:    SeverityCritical,
			Weight:      25,
			CWE:         "CWE-319: Cleartext Transmission of Sensitive Information",
			Description: "Standard unencrypted Modbus TCP port 502 traffic is exposed across WAN/IT network boundaries without Modbus Security (Port 802 TLS) or an IPsec/WireGuard VPN tunnel.",
			Remediation: "Set 'wan_port_502_exposed: false' and 'require_tls_802_or_tunnel: true' to encapsulate field communications across untrusted routing segments.",
		})
		deductions += 25
	}

	// Rule 4: LH-MODBUS-004 (HIGH, 10 pts, CWE-20)
	if !policy.StrictMbapPduValidation {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-004",
			Title:       "Missing Strict MBAP Header and PDU Protocol Validation",
			Severity:    SeverityHigh,
			Weight:      10,
			CWE:         "CWE-20: Improper Input Validation",
			Description: "Firewall does not strictly validate MBAP header Protocol ID (0x0000), wire length alignment, or coil write values (strictly 0x0000 or 0xFF00), leaving endpoints vulnerable to protocol fuzzing.",
			Remediation: "Enable 'strict_mbap_pdu_validation: true' to reject non-conformant MBAP headers, length mismatches, and malformed payload values.",
		})
		deductions += 10
	}

	// Rule 5: LH-MODBUS-005 (HIGH, 10 pts, CWE-285)
	if !policy.EnforceRegisterAddressBounds || !policy.EnforceSetpointValueLimits || len(policy.RegisterRules) == 0 {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-005",
			Title:       "Unbounded Register Address Ranges or Unconstrained Setpoints",
			Severity:    SeverityHigh,
			Weight:      10,
			CWE:         "CWE-285: Improper Authorization",
			Description: "Register addresses and physical setpoint envelopes are unconstrained. An attacker can write out-of-range setpoints that cause physical equipment damage or unsafe operating states.",
			Remediation: "Configure 'enforce_register_address_bounds: true', 'enforce_setpoint_value_limits: true', and define explicit min/max value envelopes in 'register_rules'.",
		})
		deductions += 10
	}

	// Rule 6: LH-MODBUS-006 (HIGH, 10 pts, CWE-290)
	if !policy.BlockUnitIDZeroBroadcast || !policy.UnitIDAllowlistEnabled || len(policy.AllowedUnitIDs) == 0 {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-006",
			Title:       "Permissive Unit ID Zero Broadcast or Gateway Routing Allowed",
			Severity:    SeverityHigh,
			Weight:      10,
			CWE:         "CWE-290: Authentication Bypass by Spoofing",
			Description: "Modbus broadcast address (Unit ID 0) or unverified slave addresses are accepted. Attackers can broadcast destructive writes across all downstream RS-485 serial multidrop instruments.",
			Remediation: "Enable 'block_unit_id_zero_broadcast: true', 'unit_id_allowlist_enabled: true', and configure explicit 'allowed_unit_ids'.",
		})
		deductions += 10
	}

	// Rule 7: LH-MODBUS-007 (HIGH, 10 pts, CWE-400)
	if !policy.RateLimitingEnabled || policy.MaxRequestsPerSec > 200 || policy.MaxRequestsPerSec <= 0 || policy.MaxConcurrentTCPSessions > 16 || policy.MaxConcurrentTCPSessions <= 0 {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-007",
			Title:       "Excessive Polling Frequency or Unbounded Concurrent TCP Sessions",
			Severity:    SeverityHigh,
			Weight:      10,
			CWE:         "CWE-400: Uncontrolled Resource Consumption",
			Description: "Polling rate limit exceeds 200 requests per second or concurrent TCP sessions exceed 16, exposing RTU gateway serial buffers and low-power PLC microcontrollers to resource starvation.",
			Remediation: "Enable 'rate_limiting_enabled: true', constrain 'max_requests_per_sec' to <= 200, and clamp 'max_concurrent_tcp_sessions' to <= 16.",
		})
		deductions += 10
	}

	// Rule 8: LH-MODBUS-008 (MEDIUM, 4 pts, CWE-345)
	if !policy.StatefulTransactionTracking {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-008",
			Title:       "Stateless Transaction Tracking (Missing MBAP Transaction ID Correlation)",
			Severity:    SeverityMedium,
			Weight:      4,
			CWE:         "CWE-345: Insufficient Verification of Data Authenticity",
			Description: "Transaction correlation is disabled. Responses are processed without matching prior requests, allowing blind injection of unsolicited responses or transaction desynchronization.",
			Remediation: "Enable 'stateful_transaction_tracking: true' to correlate MBAP Transaction IDs and verify matching function codes between requests and responses.",
		})
		deductions += 4
	}

	// Rule 9: LH-MODBUS-009 (MEDIUM, 4 pts, CWE-693)
	if !policy.RegisterSlewRateGuard {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-009",
			Title:       "Missing Physical Slew-Rate / Sudden Step-Change Limiter",
			Severity:    SeverityMedium,
			Weight:      4,
			CWE:         "CWE-693: Protection Mechanism Failure",
			Description: "Sudden setpoint step changes are permitted without maximum delta (slew-rate) limits, creating risk of water hammer, pressure surges, or thermal shock to physical equipment.",
			Remediation: "Enable 'register_slew_rate_guard: true' and configure 'max_slew_rate' step change limits on critical actuator registers.",
		})
		deductions += 4
	}

	// Rule 10: LH-MODBUS-010 (LOW, 1 pt, CWE-778)
	if !policy.LogExceptionScans || !policy.OtSiemAuditLogging {
		report.Findings = append(report.Findings, AuditFinding{
			RuleID:      "LH-MODBUS-010",
			Title:       "Modbus Exception Code Scanning and OT SIEM Telemetry Disabled",
			Severity:    SeverityLow,
			Weight:      1,
			CWE:         "CWE-778: Insufficient Logging",
			Description: "Exception response scanning and OT SIEM audit telemetry are disabled, preventing SOC/OT analysts from detecting reconnaissance or brute-force register discovery sweeps.",
			Remediation: "Enable both 'log_exception_scans: true' and 'ot_siem_audit_logging: true' for security event streaming to industrial SIEM systems.",
		})
		deductions += 1
	}

	report.FailedRules = len(report.Findings)
	report.PassedRules = report.TotalRules - report.FailedRules

	score := 100 - deductions
	if score < 0 {
		score = 0
	}
	report.Score = score

	if report.Score == 100 {
		report.Status = "HARDENED"
	} else if report.Score >= 85 {
		report.Status = "ADEQUATE"
	} else if report.Score >= 60 {
		report.Status = "ELEVATED_RISK"
	} else {
		report.Status = "CRITICAL_RISK"
	}

	return report
}
