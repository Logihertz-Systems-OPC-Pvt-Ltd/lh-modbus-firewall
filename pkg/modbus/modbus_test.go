package modbus

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCRC16Computation(t *testing.T) {
	// Standard Modbus test vector:
	// Slave ID: 01, Function: 03, Start: 00 00, Quantity: 00 0A
	// The CRC-16 is 0xCDC5. Transmitted on wire as C5 CD (low byte first).
	req := []byte{0x01, 0x03, 0x00, 0x00, 0x00, 0x0A}
	crc := ComputeCRC16(req)
	expectedCRC := uint16(0xCDC5)
	if crc != expectedCRC {
		t.Fatalf("ComputeCRC16 failed: expected 0x%04X, got 0x%04X", expectedCRC, crc)
	}

	appended := AppendCRC16(req)
	if len(appended) != len(req)+2 {
		t.Fatalf("AppendCRC16 wrong length: expected %d, got %d", len(req)+2, len(appended))
	}
	if appended[6] != 0xC5 || appended[7] != 0xCD {
		t.Fatalf("AppendCRC16 wrong wire byte order: expected C5 CD, got %02X %02X", appended[6], appended[7])
	}

	ok, actual, expected := ValidateRTUCRC(appended)
	if !ok || actual != expectedCRC || expected != expectedCRC {
		t.Fatalf("ValidateRTUCRC failed on valid frame: ok=%t, actual=0x%04X, expected=0x%04X", ok, actual, expected)
	}

	// Corrupt a byte
	appended[3] = 0xFF
	okCorrupt, _, _ := ValidateRTUCRC(appended)
	if okCorrupt {
		t.Fatalf("ValidateRTUCRC passed on corrupted frame")
	}

	// Test short frame
	short := []byte{0x01, 0x03}
	okShort, _, _ := ValidateRTUCRC(short)
	if okShort {
		t.Fatalf("ValidateRTUCRC should return false for frame < 3 bytes")
	}

	fmtStr := FormatCRC(crc)
	if !strings.Contains(fmtStr, "0xCDC5") || !strings.Contains(fmtStr, "C5 CD") {
		t.Fatalf("FormatCRC output unexpected: %s", fmtStr)
	}
}

func TestDissectTCPReadHoldingRegisters(t *testing.T) {
	// TxID: 00 01, Proto: 00 00, Length: 00 06, Unit: 01, FC: 03, Start: 00 64 (100), Qty: 00 0A (10)
	raw := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x0A}
	frame, err := DissectTCP(raw)
	if err != nil {
		t.Fatalf("DissectTCP failed: %v", err)
	}

	if frame.MBAP.TransactionID != 1 {
		t.Errorf("expected TxID 1, got %d", frame.MBAP.TransactionID)
	}
	if frame.MBAP.ProtocolID != 0 {
		t.Errorf("expected ProtocolID 0, got %d", frame.MBAP.ProtocolID)
	}
	if frame.MBAP.Length != 6 {
		t.Errorf("expected Length 6, got %d", frame.MBAP.Length)
	}
	if frame.MBAP.UnitID != 1 {
		t.Errorf("expected UnitID 1, got %d", frame.MBAP.UnitID)
	}
	if frame.PDU.FunctionCode != FCReadHoldingRegisters {
		t.Errorf("expected FC 3, got %d", frame.PDU.FunctionCode)
	}
	if frame.PDU.StartAddress != 100 {
		t.Errorf("expected StartAddress 100, got %d", frame.PDU.StartAddress)
	}
	if frame.PDU.Quantity != 10 {
		t.Errorf("expected Quantity 10, got %d", frame.PDU.Quantity)
	}
	if len(frame.Anomalies) != 0 {
		t.Errorf("expected 0 anomalies, got %v", frame.Anomalies)
	}
}

func TestDissectTCPWriteSingleCoil(t *testing.T) {
	// Coil ON: 0xFF00
	rawOn := []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0xFF, 0x00}
	frameOn, err := DissectTCP(rawOn)
	if err != nil {
		t.Fatalf("DissectTCP failed: %v", err)
	}
	if frameOn.PDU.Value != CoilValueOn {
		t.Errorf("expected CoilValueOn, got 0x%04X", frameOn.PDU.Value)
	}
	if len(frameOn.Anomalies) != 0 {
		t.Errorf("unexpected anomalies on valid coil ON: %v", frameOn.Anomalies)
	}

	// Coil OFF: 0x0000
	rawOff := []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0x00, 0x00}
	frameOff, err := DissectTCP(rawOff)
	if err != nil {
		t.Fatalf("DissectTCP failed: %v", err)
	}
	if frameOff.PDU.Value != CoilValueOff {
		t.Errorf("expected CoilValueOff, got 0x%04X", frameOff.PDU.Value)
	}

	// Coil Invalid: 0x1234
	rawBad := []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0x12, 0x34}
	frameBad, err := DissectTCP(rawBad)
	if err != nil {
		t.Fatalf("DissectTCP failed: %v", err)
	}
	if len(frameBad.Anomalies) == 0 {
		t.Errorf("expected anomaly on invalid coil value 0x1234")
	}
}

func TestDissectTCPWriteMultipleRegisters(t *testing.T) {
	// Write 2 registers starting at address 100: values 500 (0x01F4) and 600 (0x0258)
	// TxID 00 03, Proto 00 00, Length 00 0B (11), Unit 01, FC 10, Addr 00 64, Qty 00 02, ByteCount 04, Values: 01 F4 02 58
	raw := []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x0B, 0x01, 0x10, 0x00, 0x64, 0x00, 0x02, 0x04, 0x01, 0xF4, 0x02, 0x58}
	frame, err := DissectTCP(raw)
	if err != nil {
		t.Fatalf("DissectTCP failed: %v", err)
	}
	if frame.PDU.FunctionCode != FCWriteMultipleRegisters {
		t.Errorf("expected FCWriteMultipleRegisters, got %d", frame.PDU.FunctionCode)
	}
	if frame.PDU.Quantity != 2 {
		t.Errorf("expected quantity 2, got %d", frame.PDU.Quantity)
	}
	if frame.PDU.ByteCount != 4 {
		t.Errorf("expected byte count 4, got %d", frame.PDU.ByteCount)
	}
	if len(frame.PDU.RegisterValues) != 2 || frame.PDU.RegisterValues[0] != 500 || frame.PDU.RegisterValues[1] != 600 {
		t.Errorf("expected register values [500, 600], got %v", frame.PDU.RegisterValues)
	}
	if len(frame.Anomalies) != 0 {
		t.Errorf("unexpected anomalies: %v", frame.Anomalies)
	}
}

func TestDissectDiagnosticAndProprietary(t *testing.T) {
	// Diagnostic FC 08, Sub-function 0x0001 (Restart Comms)
	rawDiag := []byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x01, 0x08, 0x00, 0x01, 0x00, 0x00}
	frameDiag, err := DissectTCP(rawDiag)
	if err != nil {
		t.Fatalf("DissectTCP failed: %v", err)
	}
	if frameDiag.PDU.SubFunction != SubFCRestartCommunicationsOption {
		t.Errorf("expected SubFunction 0x0001, got 0x%04X", frameDiag.PDU.SubFunction)
	}
	if len(frameDiag.Anomalies) == 0 {
		t.Errorf("expected anomaly for diagnostic FC 08")
	}

	// Schneider UMAS FC 0x5A
	rawUMAS := []byte{0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x01, 0x5A, 0x00}
	frameUMAS, err := DissectTCP(rawUMAS)
	if err != nil {
		t.Fatalf("DissectTCP failed: %v", err)
	}
	if frameUMAS.PDU.FunctionCode != FCUMAS {
		t.Errorf("expected FCUMAS, got 0x%02X", frameUMAS.PDU.FunctionCode)
	}
	hasUMASAnomaly := false
	for _, a := range frameUMAS.Anomalies {
		if strings.Contains(a, "UMAS") {
			hasUMASAnomaly = true
		}
	}
	if !hasUMASAnomaly {
		t.Errorf("expected UMAS alert in anomalies: %v", frameUMAS.Anomalies)
	}
}

func TestDissectExceptionResponse(t *testing.T) {
	// Response with Exception: FC 0x83 (Read Holding Register Exception), Exception Code 0x02 (Illegal Data Address)
	raw := []byte{0x00, 0x06, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02}
	frame, err := DissectTCP(raw)
	if err != nil {
		t.Fatalf("DissectTCP failed: %v", err)
	}
	if !frame.PDU.IsException {
		t.Errorf("expected IsException true")
	}
	if frame.PDU.FunctionCode != FCReadHoldingRegisters {
		t.Errorf("expected base FC 0x03, got %d", frame.PDU.FunctionCode)
	}
	if frame.PDU.ExceptionCode != ExpIllegalDataAddress {
		t.Errorf("expected ExceptionCode 0x02, got %d", frame.PDU.ExceptionCode)
	}
	if !strings.Contains(frame.PDU.ExceptionName, "Illegal Data Address") {
		t.Errorf("expected ExceptionName 'Illegal Data Address', got %q", frame.PDU.ExceptionName)
	}
}

func TestDissectAnomalousHeaders(t *testing.T) {
	// Non-zero protocol ID
	rawProto := []byte{0x00, 0x01, 0x12, 0x34, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01}
	f1, _ := DissectTCP(rawProto)
	foundProto := false
	for _, a := range f1.Anomalies {
		if strings.Contains(a, "Protocol ID") {
			foundProto = true
		}
	}
	if !foundProto {
		t.Errorf("expected Protocol ID anomaly")
	}

	// Length field mismatch: declared length 20, wire length 12
	rawLen := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01}
	f2, _ := DissectTCP(rawLen)
	foundLen := false
	for _, a := range f2.Anomalies {
		if strings.Contains(a, "length mismatch") {
			foundLen = true
		}
	}
	if !foundLen {
		t.Errorf("expected length mismatch anomaly")
	}

	// Unit ID 0 (Broadcast)
	rawBcast := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01}
	f3, _ := DissectTCP(rawBcast)
	foundBcast := false
	for _, a := range f3.Anomalies {
		if strings.Contains(a, "broadcast") {
			foundBcast = true
		}
	}
	if !foundBcast {
		t.Errorf("expected broadcast anomaly")
	}

	// Too short
	_, errShort := DissectTCP([]byte{0x00, 0x01})
	if errShort == nil {
		t.Errorf("expected error on truncated header")
	}
}

func TestParseHexFrame(t *testing.T) {
	// Hex with spaces, 0x prefix, and colons
	hexInput := "0x00:01 00:00 00:06 01:03 00:64 00:0A"
	frame, err := ParseHexFrame(hexInput)
	if err != nil {
		t.Fatalf("ParseHexFrame failed: %v", err)
	}
	if frame.MBAP.TransactionID != 1 || frame.PDU.Quantity != 10 {
		t.Errorf("parsed frame fields mismatch: %+v", frame)
	}

	// RTU frame in hex
	rtuHex := "01030000000AC5CD"
	rtuFrame, err := ParseHexFrame(rtuHex)
	if err != nil {
		t.Fatalf("ParseHexFrame RTU failed: %v", err)
	}
	if rtuFrame.IsTCP {
		t.Errorf("expected RTU frame, got TCP")
	}
	if !rtuFrame.CRCOk {
		t.Errorf("expected valid RTU CRC")
	}

	// Bad hex
	_, errBad := ParseHexFrame("NOT_HEX")
	if errBad == nil {
		t.Errorf("expected error on invalid hex string")
	}
}

func createHardenedPolicy() *FirewallPolicy {
	minVal := uint16(100)
	maxVal := uint16(1800)
	maxSlew := uint16(200)

	minVal101 := uint16(0)
	maxVal101 := uint16(100)
	maxSlew101 := uint16(50)

	return &FirewallPolicy{
		Name:                             "Test Hardened Policy",
		AllowUnrestrictedWrites:          false,
		AllowedWriteClientIPs:            []string{"192.168.10.15", "192.168.10.20"},
		BlockDiagnosticAndProprietaryFCs: true,
		WanPort502Exposed:                false,
		RequireTLS802OrTunnel:            true,
		StrictMbapPduValidation:          true,
		EnforceRegisterAddressBounds:     true,
		EnforceSetpointValueLimits:       true,
		BlockUnitIDZeroBroadcast:         true,
		UnitIDAllowlistEnabled:           true,
		AllowedUnitIDs:                   []uint8{1, 2, 3},
		RateLimitingEnabled:              true,
		MaxRequestsPerSec:                100,
		MaxConcurrentTCPSessions:         8,
		StatefulTransactionTracking:      true,
		RegisterSlewRateGuard:            true,
		LogExceptionScans:                true,
		OtSiemAuditLogging:               true,
		AllowedFunctionCodes:             []uint8{1, 2, 3, 4, 5, 6, 15, 16},
		RegisterRules: []RegisterRule{
			{
				Address:     100,
				Name:        "Coolant Pump Speed",
				ReadOnly:    false,
				MinValue:    &minVal,
				MaxValue:    &maxVal,
				MaxSlewRate: &maxSlew,
			},
			{
				Address:     101,
				Name:        "Emergency Valve Cutoff",
				ReadOnly:    false,
				MinValue:    &minVal101,
				MaxValue:    &maxVal101,
				MaxSlewRate: &maxSlew101,
			},
			{
				Address:  102,
				Name:     "Turbine RPM Sensor",
				ReadOnly: true,
			},
		},
	}
}

func createVulnerablePolicy() *FirewallPolicy {
	return &FirewallPolicy{
		Name:                             "Test Vulnerable Policy",
		AllowUnrestrictedWrites:          true,
		AllowedWriteClientIPs:            []string{},
		BlockDiagnosticAndProprietaryFCs: false,
		WanPort502Exposed:                true,
		RequireTLS802OrTunnel:            false,
		StrictMbapPduValidation:          false,
		EnforceRegisterAddressBounds:     false,
		EnforceSetpointValueLimits:       false,
		BlockUnitIDZeroBroadcast:         false,
		UnitIDAllowlistEnabled:           false,
		AllowedUnitIDs:                   []uint8{},
		RateLimitingEnabled:              false,
		MaxRequestsPerSec:                500,
		MaxConcurrentTCPSessions:         64,
		StatefulTransactionTracking:      false,
		RegisterSlewRateGuard:            false,
		LogExceptionScans:                false,
		OtSiemAuditLogging:               false,
		AllowedFunctionCodes:             []uint8{},
		RegisterRules:                    []RegisterRule{},
	}
}

func TestAuditorHardenedPolicy(t *testing.T) {
	p := createHardenedPolicy()
	report := AuditPolicy(p)

	if report.Score != 100 {
		t.Fatalf("expected hardened score 100, got %d (findings: %+v)", report.Score, report.Findings)
	}
	if report.Status != "HARDENED" {
		t.Errorf("expected status HARDENED, got %s", report.Status)
	}
	if report.PassedRules != 10 || report.FailedRules != 0 {
		t.Errorf("expected 10 passed and 0 failed, got %d passed, %d failed", report.PassedRules, report.FailedRules)
	}
}

func TestAuditorVulnerablePolicy(t *testing.T) {
	p := createVulnerablePolicy()
	report := AuditPolicy(p)

	if report.Score != 0 {
		t.Fatalf("expected vulnerable score 0, got %d", report.Score)
	}
	if report.Status != "CRITICAL_RISK" {
		t.Errorf("expected status CRITICAL_RISK, got %s", report.Status)
	}
	if report.FailedRules != 10 {
		t.Errorf("expected 10 failed rules, got %d", report.FailedRules)
	}
}

func TestAuditorRuleToggles(t *testing.T) {
	// Test LH-MODBUS-001 deduction
	p1 := createHardenedPolicy()
	p1.AllowUnrestrictedWrites = true
	r1 := AuditPolicy(p1)
	if r1.Score != 75 || len(r1.Findings) != 1 || r1.Findings[0].RuleID != "LH-MODBUS-001" {
		t.Errorf("expected LH-MODBUS-001 trigger: score %d", r1.Score)
	}

	// Test LH-MODBUS-002 deduction
	p2 := createHardenedPolicy()
	p2.BlockDiagnosticAndProprietaryFCs = false
	r2 := AuditPolicy(p2)
	if r2.Score != 75 || len(r2.Findings) != 1 || r2.Findings[0].RuleID != "LH-MODBUS-002" {
		t.Errorf("expected LH-MODBUS-002 trigger: score %d", r2.Score)
	}

	// Test LH-MODBUS-003 deduction
	p3 := createHardenedPolicy()
	p3.WanPort502Exposed = true
	r3 := AuditPolicy(p3)
	if r3.Score != 75 || len(r3.Findings) != 1 || r3.Findings[0].RuleID != "LH-MODBUS-003" {
		t.Errorf("expected LH-MODBUS-003 trigger: score %d", r3.Score)
	}

	// Test LH-MODBUS-004 deduction
	p4 := createHardenedPolicy()
	p4.StrictMbapPduValidation = false
	r4 := AuditPolicy(p4)
	if r4.Score != 90 || len(r4.Findings) != 1 || r4.Findings[0].RuleID != "LH-MODBUS-004" {
		t.Errorf("expected LH-MODBUS-004 trigger: score %d", r4.Score)
	}

	// Test LH-MODBUS-005 deduction
	p5 := createHardenedPolicy()
	p5.EnforceSetpointValueLimits = false
	r5 := AuditPolicy(p5)
	if r5.Score != 90 || len(r5.Findings) != 1 || r5.Findings[0].RuleID != "LH-MODBUS-005" {
		t.Errorf("expected LH-MODBUS-005 trigger: score %d", r5.Score)
	}

	// Test LH-MODBUS-006 deduction
	p6 := createHardenedPolicy()
	p6.BlockUnitIDZeroBroadcast = false
	r6 := AuditPolicy(p6)
	if r6.Score != 90 || len(r6.Findings) != 1 || r6.Findings[0].RuleID != "LH-MODBUS-006" {
		t.Errorf("expected LH-MODBUS-006 trigger: score %d", r6.Score)
	}

	// Test LH-MODBUS-007 deduction
	p7 := createHardenedPolicy()
	p7.MaxRequestsPerSec = 500
	r7 := AuditPolicy(p7)
	if r7.Score != 90 || len(r7.Findings) != 1 || r7.Findings[0].RuleID != "LH-MODBUS-007" {
		t.Errorf("expected LH-MODBUS-007 trigger: score %d", r7.Score)
	}

	// Test LH-MODBUS-008 deduction
	p8 := createHardenedPolicy()
	p8.StatefulTransactionTracking = false
	r8 := AuditPolicy(p8)
	if r8.Score != 96 || len(r8.Findings) != 1 || r8.Findings[0].RuleID != "LH-MODBUS-008" {
		t.Errorf("expected LH-MODBUS-008 trigger: score %d", r8.Score)
	}

	// Test LH-MODBUS-009 deduction
	p9 := createHardenedPolicy()
	p9.RegisterSlewRateGuard = false
	r9 := AuditPolicy(p9)
	if r9.Score != 96 || len(r9.Findings) != 1 || r9.Findings[0].RuleID != "LH-MODBUS-009" {
		t.Errorf("expected LH-MODBUS-009 trigger: score %d", r9.Score)
	}

	// Test LH-MODBUS-010 deduction
	p10 := createHardenedPolicy()
	p10.LogExceptionScans = false
	r10 := AuditPolicy(p10)
	if r10.Score != 99 || len(r10.Findings) != 1 || r10.Findings[0].RuleID != "LH-MODBUS-010" {
		t.Errorf("expected LH-MODBUS-010 trigger: score %d", r10.Score)
	}
}

func TestFirewallEngineSecurityEnforcement(t *testing.T) {
	policy := createHardenedPolicy()
	engine := NewFirewallEngine(policy)
	now := time.Now()

	// 1. Authorized read from authorized IP
	readFrame, _ := ParseHexFrame("00010000000601030064000A")
	v1 := engine.EvaluatePacket("192.168.10.15", readFrame, false, now)
	if !v1.Accepted {
		t.Errorf("expected authorized read accepted, got DROP: %v", v1.Reasons)
	}

	// 2. Unauthorized write from unknown IP
	writeFrame, _ := ParseHexFrame("0002000000060106006401F4")
	v2 := engine.EvaluatePacket("10.0.0.99", writeFrame, false, now)
	if v2.Accepted || v2.RuleID != "LH-MODBUS-001" {
		t.Errorf("expected unauthorized IP write to drop with LH-MODBUS-001, got %+v", v2)
	}

	// 3. Authorized write setting register 100 to 500
	v3 := engine.EvaluatePacket("192.168.10.15", writeFrame, false, now)
	if !v3.Accepted {
		t.Errorf("expected authorized write accepted, got: %v", v3.Reasons)
	}
	regVal, ok := engine.GetRegisterValue(100)
	if !ok || regVal != 500 {
		t.Errorf("expected register 100 state to be 500, got %d (ok: %t)", regVal, ok)
	}

	// 4. Slew-rate violation: attempt to jump register 100 from 500 to 1200 (delta 700 > max 200)
	slewFrame, _ := ParseHexFrame("0003000000060106006404B0")
	v4 := engine.EvaluatePacket("192.168.10.15", slewFrame, false, now)
	if v4.Accepted || v4.RuleID != "LH-MODBUS-009" {
		t.Errorf("expected slew rate drop with LH-MODBUS-009, got %+v", v4)
	}

	// 5. Valid slew-rate step: jump from 500 to 650 (delta 150 <= max 200)
	validStepFrame, _ := ParseHexFrame("00040000000601060064028A")
	v5 := engine.EvaluatePacket("192.168.10.15", validStepFrame, false, now)
	if !v5.Accepted {
		t.Errorf("expected step of 150 accepted within slew limit 200, got drop: %v", v5.Reasons)
	}

	// 6. Setpoint bounds underflow: write 50 (below min 100)
	underFrame, _ := ParseHexFrame("000500000006010600640032")
	v6 := engine.EvaluatePacket("192.168.10.15", underFrame, false, now)
	if v6.Accepted || v6.RuleID != "LH-MODBUS-005" {
		t.Errorf("expected setpoint underflow drop, got %+v", v6)
	}

	// 7. Setpoint bounds overflow: write 3000 (above max 1800)
	overFrame, _ := ParseHexFrame("000600000006010600640BB8")
	v7 := engine.EvaluatePacket("192.168.10.15", overFrame, false, now)
	if v7.Accepted || v7.RuleID != "LH-MODBUS-005" {
		t.Errorf("expected setpoint overflow drop, got %+v", v7)
	}

	// 8. Read-only register tampering: write to register 102
	roFrame, _ := ParseHexFrame("000700000006010600660100")
	v8 := engine.EvaluatePacket("192.168.10.15", roFrame, false, now)
	if v8.Accepted || v8.RuleID != "LH-MODBUS-005" {
		t.Errorf("expected read-only register drop, got %+v", v8)
	}

	// 9. Schneider UMAS PLC stop exploit code 0x5A
	umasFrame, _ := ParseHexFrame("000800000003015A01")
	v9 := engine.EvaluatePacket("192.168.10.15", umasFrame, false, now)
	if v9.Accepted || v9.RuleID != "LH-MODBUS-002" {
		t.Errorf("expected UMAS 0x5A drop with LH-MODBUS-002, got %+v", v9)
	}

	// 10. Broadcast Unit ID 0
	bcastFrame, _ := ParseHexFrame("000900000006000600640200")
	v10 := engine.EvaluatePacket("192.168.10.15", bcastFrame, false, now)
	if v10.Accepted || v10.RuleID != "LH-MODBUS-006" {
		t.Errorf("expected Unit ID 0 broadcast drop, got %+v", v10)
	}

	// 11. Unauthorized slave Unit ID 99
	badUnitFrame, _ := ParseHexFrame("000A00000006630300010001")
	v11 := engine.EvaluatePacket("192.168.10.15", badUnitFrame, false, now)
	if v11.Accepted || v11.RuleID != "LH-MODBUS-006" {
		t.Errorf("expected unauthorized Unit ID drop, got %+v", v11)
	}

	// 12. Malformed coil write value
	badCoilFrame, _ := ParseHexFrame("000B00000006010500011234")
	v12 := engine.EvaluatePacket("192.168.10.15", badCoilFrame, false, now)
	if v12.Accepted || v12.RuleID != "LH-MODBUS-004" {
		t.Errorf("expected malformed coil value drop, got %+v", v12)
	}
}

func TestStatefulTransactionTracking(t *testing.T) {
	policy := createHardenedPolicy()
	engine := NewFirewallEngine(policy)
	now := time.Now()

	// Step 1: Send request with TxID 42, FC 03
	reqFrame, _ := ParseHexFrame("002A00000006010300640005")
	vReq := engine.EvaluatePacket("192.168.10.15", reqFrame, false, now)
	if !vReq.Accepted {
		t.Fatalf("request unexpectedly dropped: %v", vReq.Reasons)
	}

	// Step 2: Send unsolicited response (TxID 99, never requested)
	unsolicitedResp, _ := ParseHexFrame("0063000000050103020100")
	vUnsolicited := engine.EvaluatePacket("192.168.10.2", unsolicitedResp, true, now)
	if vUnsolicited.Accepted || vUnsolicited.RuleID != "LH-MODBUS-008" {
		t.Errorf("expected unsolicited response to drop with LH-MODBUS-008, got %+v", vUnsolicited)
	}

	// Step 3: Send matching response for TxID 42
	matchingResp, _ := ParseHexFrame("002A000000050103020100")
	vMatch := engine.EvaluatePacket("192.168.10.2", matchingResp, true, now)
	if !vMatch.Accepted {
		t.Errorf("expected matching response to be accepted, got: %v", vMatch.Reasons)
	}

	// Step 4: Replay response for TxID 42 (already consumed, should now be treated as unsolicited)
	vReplay := engine.EvaluatePacket("192.168.10.2", matchingResp, true, now)
	if vReplay.Accepted || vReplay.RuleID != "LH-MODBUS-008" {
		t.Errorf("expected replayed response to drop with LH-MODBUS-008, got %+v", vReplay)
	}
}

func TestTokenBucketRateLimiting(t *testing.T) {
	tb := NewTokenBucket(10, 5) // 10 tokens/sec, max 5 capacity
	now := time.Now()

	// Should allow initial 5 burst requests
	for i := 0; i < 5; i++ {
		if !tb.Allow(now) {
			t.Fatalf("expected token available at index %d", i)
		}
	}

	// 6th request at same instant should be denied
	if tb.Allow(now) {
		t.Fatalf("expected rate limit exhaustion on 6th request")
	}

	// Advance time by 0.5s -> should replenish 5 tokens
	nowLater := now.Add(500 * time.Millisecond)
	if !tb.Allow(nowLater) {
		t.Fatalf("expected token available after refill time")
	}
}

func TestExporters(t *testing.T) {
	policy := createHardenedPolicy()
	report := AuditPolicy(policy)

	// ANSI table render
	tbl := RenderAuditTable(report)
	if !strings.Contains(tbl, "POSTURE AUDIT REPORT") || !strings.Contains(tbl, "100 / 100") {
		t.Errorf("RenderAuditTable missing key content: %s", tbl)
	}

	// JSON render
	jsonStr, err := ToJSON(report)
	if err != nil || !strings.Contains(jsonStr, `"score": 100`) {
		t.Errorf("ToJSON failed: %v, output: %s", err, jsonStr)
	}

	// SARIF render
	sarifStr, err := ToSARIF(report)
	if err != nil || !strings.Contains(sarifStr, `"version": "2.1.0"`) {
		t.Errorf("ToSARIF failed: %v, output: %s", err, sarifStr)
	}

	// Frame table render
	frame, _ := ParseHexFrame("00010000000601030064000A")
	frameTbl := RenderFrameTable(frame)
	if !strings.Contains(frameTbl, "DEEP PACKET INSPECTION") || !strings.Contains(frameTbl, "Read Holding Registers") {
		t.Errorf("RenderFrameTable missing key content: %s", frameTbl)
	}

	// Trace table render
	tr := &TraceResult{
		TotalPackets:    2,
		AcceptedPackets: 1,
		DroppedPackets:  1,
		Evaluations: []PacketEvaluation{
			{
				Index:    1,
				ClientIP: "192.168.10.15",
				Frame:    *frame,
				Verdict:  DPIVerdict{Accepted: true, Action: "ACCEPT"},
			},
			{
				Index:    2,
				ClientIP: "10.0.0.99",
				Frame:    *frame,
				Verdict:  DPIVerdict{Accepted: false, Action: "DROP", RuleID: "LH-MODBUS-001", Reasons: []string{"unauthorized"}},
			},
		},
		EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	trTbl := RenderTraceTable(tr)
	if !strings.Contains(trTbl, "EVALUATION SUMMARY") || !strings.Contains(trTbl, "ACCEPT") || !strings.Contains(trTbl, "DROP") {
		t.Errorf("RenderTraceTable missing key content: %s", trTbl)
	}

	trSARIF, err := TraceToSARIF(tr)
	if err != nil || !strings.Contains(trSARIF, "LH-MODBUS-001") {
		t.Errorf("TraceToSARIF failed: %v, output: %s", err, trSARIF)
	}
}

func TestSampleTraceEvaluation(t *testing.T) {
	// Parse sample trace from fixture structure
	policy := createHardenedPolicy()
	engine := NewFirewallEngine(policy)

	traceBytes := []byte(`[
		{"client_ip": "192.168.10.15", "hex_data": "00010000000601030064000A", "is_response": false},
		{"client_ip": "192.168.10.15", "hex_data": "0002000000060106006401F4", "is_response": false},
		{"client_ip": "10.0.0.99", "hex_data": "000300000006010600640226", "is_response": false},
		{"client_ip": "192.168.10.15", "hex_data": "000400000003015A01", "is_response": false},
		{"client_ip": "192.168.10.15", "hex_data": "000500000006010500011234", "is_response": false},
		{"client_ip": "192.168.10.15", "hex_data": "000600000006010600641388", "is_response": false},
		{"client_ip": "192.168.10.15", "hex_data": "0007000000060106006603E8", "is_response": false},
		{"client_ip": "192.168.10.15", "hex_data": "000800000006000600640200", "is_response": false},
		{"client_ip": "192.168.10.15", "hex_data": "000900000006630300010001", "is_response": false},
		{"client_ip": "192.168.10.15", "hex_data": "000A000000060106006404B0", "is_response": false}
	]`)

	var packets []TracePacket
	if err := json.Unmarshal(traceBytes, &packets); err != nil {
		t.Fatalf("failed unmarshaling test trace: %v", err)
	}

	acceptedCount := 0
	droppedCount := 0

	for i, pkt := range packets {
		frame, err := ParseHexFrame(pkt.HexData)
		if err != nil {
			t.Fatalf("packet %d failed parsing: %v", i+1, err)
		}
		verdict := engine.EvaluatePacket(pkt.ClientIP, frame, pkt.IsResponse, time.Now())
		if verdict.Accepted {
			acceptedCount++
		} else {
			droppedCount++
		}
	}

	// Packets 1 and 2 should be accepted, remaining 8 should be dropped
	if acceptedCount != 2 || droppedCount != 8 {
		t.Errorf("expected 2 accepted and 8 dropped in trace, got %d accepted, %d dropped", acceptedCount, droppedCount)
	}
}
