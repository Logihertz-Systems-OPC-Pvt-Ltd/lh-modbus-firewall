package modbus

import (
	"time"
)

// Standard Modbus Function Codes per Modbus Application Protocol Specification V1.1b3
const (
	FCReadCoils                  uint8 = 0x01
	FCReadDiscreteInputs         uint8 = 0x02
	FCReadHoldingRegisters       uint8 = 0x03
	FCReadInputRegisters         uint8 = 0x04
	FCWriteSingleCoil            uint8 = 0x05
	FCWriteSingleRegister        uint8 = 0x06
	FCReadExceptionStatus        uint8 = 0x07
	FCDiagnostic                 uint8 = 0x08
	FCGetCommEventCounter        uint8 = 0x0B
	FCGetCommEventLog            uint8 = 0x0C
	FCWriteMultipleCoils         uint8 = 0x0F
	FCWriteMultipleRegisters     uint8 = 0x10
	FCReportServerID             uint8 = 0x11
	FCReadFileRecord             uint8 = 0x14
	FCWriteFileRecord            uint8 = 0x15
	FCMaskWriteRegister          uint8 = 0x16
	FCReadWriteMultipleRegisters uint8 = 0x17
	FCReadFIFOQueue              uint8 = 0x18
	FCEncapsulatedInterface      uint8 = 0x2B // Read Device Identification (MEI)

	// Vendor-specific & dangerous function codes
	FCUMAS uint8 = 0x5A // Schneider Electric UMAS (PLC stop, memory read/write)
)

// Modbus Exception Codes
const (
	ExpIllegalFunction         uint8 = 0x01
	ExpIllegalDataAddress      uint8 = 0x02
	ExpIllegalDataValue        uint8 = 0x03
	ExpServerDeviceFailure     uint8 = 0x04
	ExpAcknowledge             uint8 = 0x05
	ExpServerDeviceBusy        uint8 = 0x06
	ExpMemoryParityError       uint8 = 0x08
	ExpGatewayPathUnavailable  uint8 = 0x0A
	ExpGatewayTargetDeviceFail uint8 = 0x0B
)

// Diagnostic Sub-function Codes for FC 08
const (
	SubFCReturnQueryData              uint16 = 0x0000
	SubFCRestartCommunicationsOption  uint16 = 0x0001
	SubFCReturnDiagnosticRegister     uint16 = 0x0002
	SubFCChangeAsciiInputDelimiter    uint16 = 0x0003
	SubFCForceListenOnlyMode          uint16 = 0x0004
	SubFCClearCountersAndDiagRegister uint16 = 0x000A
	SubFCReturnBusMessageCount        uint16 = 0x000B
	SubFCReturnBusCommErrorCount      uint16 = 0x000C
	SubFCReturnBusExceptionErrorCount uint16 = 0x000D
	SubFCReturnServerMessageCount     uint16 = 0x000E
	SubFCReturnServerNoResponseCount  uint16 = 0x000F
	SubFCReturnServerNAKCount         uint16 = 0x0010
	SubFCReturnServerBusyCount        uint16 = 0x0011
	SubFCReturnBusCharacterOverrunCnt uint16 = 0x0012
	SubFCClearOverrunCounterAndFlag   uint16 = 0x0014
)

// Coil write valid constants
const (
	CoilValueOff uint16 = 0x0000
	CoilValueOn  uint16 = 0xFF00
)

// MBAPHeader represents the 7-byte Modbus Application Protocol header used in Modbus TCP.
type MBAPHeader struct {
	TransactionID uint16 `json:"transaction_id"`
	ProtocolID    uint16 `json:"protocol_id"`
	Length        uint16 `json:"length"`
	UnitID        uint8  `json:"unit_id"`
}

// ModbusPDU represents a dissected Modbus Protocol Data Unit.
type ModbusPDU struct {
	FunctionCode   uint8    `json:"function_code"`
	FunctionName   string   `json:"function_name"`
	IsException    bool     `json:"is_exception"`
	ExceptionCode  uint8    `json:"exception_code,omitempty"`
	ExceptionName  string   `json:"exception_name,omitempty"`
	SubFunction    uint16   `json:"sub_function,omitempty"`
	StartAddress   uint16   `json:"start_address,omitempty"`
	Quantity       uint16   `json:"quantity,omitempty"`
	Value          uint16   `json:"value,omitempty"`
	ByteCount      uint8    `json:"byte_count,omitempty"`
	RegisterValues []uint16 `json:"register_values,omitempty"`
	RawPayload     []byte   `json:"-"`
}

// ModbusFrame represents a dissected Modbus frame (TCP MBAP+PDU or RTU).
type ModbusFrame struct {
	MBAP      MBAPHeader `json:"mbap"`
	PDU       ModbusPDU  `json:"pdu"`
	WireLen   int        `json:"wire_len"`
	RawBytes  []byte     `json:"-"`
	IsTCP     bool       `json:"is_tcp"`
	CRC16     uint16     `json:"crc16,omitempty"`
	CRCOk     bool       `json:"crc_ok,omitempty"`
	Anomalies []string   `json:"anomalies,omitempty"`
}

// RegisterRule configures security constraints for an individual holding register or coil.
type RegisterRule struct {
	Address     uint16  `json:"address"`
	Name        string  `json:"name,omitempty"`
	ReadOnly    bool    `json:"read_only"`
	MinValue    *uint16 `json:"min_value,omitempty"`
	MaxValue    *uint16 `json:"max_value,omitempty"`
	MaxSlewRate *uint16 `json:"max_slew_rate,omitempty"`
}

// FirewallPolicy defines the comprehensive security configuration for the Modbus TCP firewall.
type FirewallPolicy struct {
	Name                             string         `json:"name"`
	AllowUnrestrictedWrites          bool           `json:"allow_unrestricted_writes"`
	AllowedWriteClientIPs            []string       `json:"allowed_write_client_ips"`
	BlockDiagnosticAndProprietaryFCs bool           `json:"block_diagnostic_and_proprietary_fcs"`
	WanPort502Exposed                bool           `json:"wan_port_502_exposed"`
	RequireTLS802OrTunnel            bool           `json:"require_tls_802_or_tunnel"`
	StrictMbapPduValidation          bool           `json:"strict_mbap_pdu_validation"`
	EnforceRegisterAddressBounds     bool           `json:"enforce_register_address_bounds"`
	EnforceSetpointValueLimits       bool           `json:"enforce_setpoint_value_limits"`
	BlockUnitIDZeroBroadcast         bool           `json:"block_unit_id_zero_broadcast"`
	UnitIDAllowlistEnabled           bool           `json:"unit_id_allowlist_enabled"`
	AllowedUnitIDs                   []uint8        `json:"allowed_unit_ids"`
	RateLimitingEnabled              bool           `json:"rate_limiting_enabled"`
	MaxRequestsPerSec                int            `json:"max_requests_per_sec"`
	MaxConcurrentTCPSessions         int            `json:"max_concurrent_tcp_sessions"`
	StatefulTransactionTracking      bool           `json:"stateful_transaction_tracking"`
	RegisterSlewRateGuard            bool           `json:"register_slew_rate_guard"`
	LogExceptionScans                bool           `json:"log_exception_scans"`
	OtSiemAuditLogging               bool           `json:"ot_siem_audit_logging"`
	AllowedFunctionCodes             []uint8        `json:"allowed_function_codes"`
	RegisterRules                    []RegisterRule `json:"register_rules"`
}

// DPIVerdict represents the decision rendered by the deep packet inspection firewall.
type DPIVerdict struct {
	Accepted  bool     `json:"accepted"`
	Action    string   `json:"action"` // "ACCEPT" or "DROP"
	Reasons   []string `json:"reasons,omitempty"`
	RuleID    string   `json:"rule_id,omitempty"`
	Timestamp string   `json:"timestamp"`
}

// TracePacket models a single packet in a packet trace file for simulation.
type TracePacket struct {
	ClientIP   string `json:"client_ip"`
	ServerIP   string `json:"server_ip"`
	HexData    string `json:"hex_data"`
	IsResponse bool   `json:"is_response,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
}

// PacketEvaluation pairs a packet trace entry with its parsed frame and firewall verdict.
type PacketEvaluation struct {
	Index    int         `json:"index"`
	ClientIP string      `json:"client_ip"`
	ServerIP string      `json:"server_ip"`
	Frame    ModbusFrame `json:"frame"`
	Verdict  DPIVerdict  `json:"verdict"`
}

// TraceResult summarizes the evaluation of a trace file.
type TraceResult struct {
	TotalPackets    int                `json:"total_packets"`
	AcceptedPackets int                `json:"accepted_packets"`
	DroppedPackets  int                `json:"dropped_packets"`
	Evaluations     []PacketEvaluation `json:"evaluations"`
	EvaluatedAt     string             `json:"evaluated_at"`
}

// Severity levels for audit findings.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// AuditFinding documents an identified posture defect or misconfiguration.
type AuditFinding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Weight      int      `json:"weight"`
	CWE         string   `json:"cwe"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
}

// AuditReport aggregates all findings for a evaluated policy.
type AuditReport struct {
	PolicyName  string         `json:"policy_name"`
	Score       int            `json:"score"`
	Status      string         `json:"status"`
	TotalRules  int            `json:"total_rules"`
	PassedRules int            `json:"passed_rules"`
	FailedRules int            `json:"failed_rules"`
	Findings    []AuditFinding `json:"findings"`
	AuditedAt   string         `json:"audited_at"`
}

// PendingTx records an in-flight request for stateful transaction correlation.
type PendingTx struct {
	TransactionID uint16
	UnitID        uint8
	FunctionCode  uint8
	ClientIP      string
	SentAt        time.Time
}
