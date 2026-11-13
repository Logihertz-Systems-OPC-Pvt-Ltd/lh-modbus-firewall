package modbus

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// TokenBucket implements a thread-safe token bucket rate limiter.
type TokenBucket struct {
	rate       float64 // tokens per second
	capacity   float64 // burst capacity
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a token bucket with specified rate and capacity.
func NewTokenBucket(rate, capacity float64) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		capacity:   capacity,
		tokens:     capacity,
		lastRefill: time.Now(),
	}
}

// Allow checks if 1 token is available and consumes it.
func (tb *TokenBucket) Allow(now time.Time) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now
	tb.tokens = math.Min(tb.capacity, tb.tokens+elapsed*tb.rate)

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

// FirewallEngine manages deep packet inspection, rate limiting, register tracking,
// and stateful transaction correlation.
type FirewallEngine struct {
	policy          *FirewallPolicy
	rateLimiters    map[string]*TokenBucket
	rateLimiterMu   sync.RWMutex
	registerStates  map[uint16]uint16
	regStateMu      sync.RWMutex
	pendingRequests map[uint32]PendingTx // key: (uint32(unitID) << 16) | uint32(txID)
	txMu            sync.RWMutex
}

// NewFirewallEngine initializes a new engine with the specified policy.
func NewFirewallEngine(policy *FirewallPolicy) *FirewallEngine {
	return &FirewallEngine{
		policy:          policy,
		rateLimiters:    make(map[string]*TokenBucket),
		registerStates:  make(map[uint16]uint16),
		pendingRequests: make(map[uint32]PendingTx),
	}
}

// Reset clears stateful trackers (useful for deterministic trace testing).
func (fe *FirewallEngine) Reset() {
	fe.rateLimiterMu.Lock()
	fe.rateLimiters = make(map[string]*TokenBucket)
	fe.rateLimiterMu.Unlock()

	fe.regStateMu.Lock()
	fe.registerStates = make(map[uint16]uint16)
	fe.regStateMu.Unlock()

	fe.txMu.Lock()
	fe.pendingRequests = make(map[uint32]PendingTx)
	fe.txMu.Unlock()
}

// SetRegisterValue pre-seeds a register state (e.g. for slew-rate testing).
func (fe *FirewallEngine) SetRegisterValue(address uint16, value uint16) {
	fe.regStateMu.Lock()
	fe.registerStates[address] = value
	fe.regStateMu.Unlock()
}

// GetRegisterValue reads the current recorded register state.
func (fe *FirewallEngine) GetRegisterValue(address uint16) (uint16, bool) {
	fe.regStateMu.RLock()
	val, ok := fe.registerStates[address]
	fe.regStateMu.RUnlock()
	return val, ok
}

// isWriteFunction returns true if the function code modifies coils or registers.
func isWriteFunction(fc uint8) bool {
	switch fc {
	case FCWriteSingleCoil, FCWriteSingleRegister, FCWriteMultipleCoils,
		FCWriteMultipleRegisters, FCWriteFileRecord, FCMaskWriteRegister,
		FCReadWriteMultipleRegisters:
		return true
	default:
		return false
	}
}

// isClientAllowedToWrite checks if the given client IP is authorized for write operations.
func (fe *FirewallEngine) isClientAllowedToWrite(clientIP string) bool {
	if fe.policy.AllowUnrestrictedWrites {
		return true
	}
	for _, ip := range fe.policy.AllowedWriteClientIPs {
		if ip == clientIP {
			return true
		}
	}
	return false
}

// isFunctionCodeAllowed checks whether the function code is permitted by policy.
func (fe *FirewallEngine) isFunctionCodeAllowed(fc uint8) bool {
	if len(fe.policy.AllowedFunctionCodes) == 0 {
		return true
	}
	for _, allowed := range fe.policy.AllowedFunctionCodes {
		if allowed == fc {
			return true
		}
	}
	return false
}

// isUnitIDAllowed checks whether the unit ID is permitted.
func (fe *FirewallEngine) isUnitIDAllowed(unitID uint8) bool {
	if !fe.policy.UnitIDAllowlistEnabled || len(fe.policy.AllowedUnitIDs) == 0 {
		return true
	}
	for _, id := range fe.policy.AllowedUnitIDs {
		if id == unitID {
			return true
		}
	}
	return false
}

// findRegisterRule locates the security rule for a specific register address.
func (fe *FirewallEngine) findRegisterRule(address uint16) *RegisterRule {
	for i := range fe.policy.RegisterRules {
		if fe.policy.RegisterRules[i].Address == address {
			return &fe.policy.RegisterRules[i]
		}
	}
	return nil
}

// getLimiter retrieves or creates a token bucket for a client IP.
func (fe *FirewallEngine) getLimiter(clientIP string) *TokenBucket {
	fe.rateLimiterMu.Lock()
	defer fe.rateLimiterMu.Unlock()

	limiter, exists := fe.rateLimiters[clientIP]
	if !exists {
		rate := float64(fe.policy.MaxRequestsPerSec)
		if rate <= 0 {
			rate = 100.0
		}
		capacity := rate * 1.5
		if capacity < 10.0 {
			capacity = 10.0
		}
		limiter = NewTokenBucket(rate, capacity)
		fe.rateLimiters[clientIP] = limiter
	}
	return limiter
}

// EvaluatePacket executes deep packet inspection on a parsed Modbus frame.
func (fe *FirewallEngine) EvaluatePacket(clientIP string, frame *ModbusFrame, isResponse bool, now time.Time) DPIVerdict {
	verdict := DPIVerdict{
		Accepted:  true,
		Action:    "ACCEPT",
		Reasons:   make([]string, 0),
		Timestamp: now.UTC().Format(time.RFC3339Nano),
	}

	drop := func(ruleID, reason string) DPIVerdict {
		verdict.Accepted = false
		verdict.Action = "DROP"
		verdict.RuleID = ruleID
		verdict.Reasons = append(verdict.Reasons, reason)
		return verdict
	}

	// 1. Strict MBAP / PDU Protocol Validation
	if fe.policy.StrictMbapPduValidation {
		if frame.IsTCP {
			if frame.MBAP.ProtocolID != 0x0000 {
				return drop("LH-MODBUS-004",
					fmt.Sprintf("Protocol ID 0x%04X is invalid for Modbus TCP (must strictly be 0x0000)", frame.MBAP.ProtocolID))
			}
			if frame.MBAP.Length < 2 || frame.MBAP.Length > 254 {
				return drop("LH-MODBUS-004",
					fmt.Sprintf("MBAP Length %d is outside valid specification range [2..254]", frame.MBAP.Length))
			}
			expectedWireLen := 6 + int(frame.MBAP.Length)
			if frame.WireLen != expectedWireLen {
				return drop("LH-MODBUS-004",
					fmt.Sprintf("MBAP Length mismatch: declared %d bytes, wire length %d bytes", frame.MBAP.Length, frame.WireLen))
			}
		}

		// Coil write validation: 0x0000 or 0xFF00
		if frame.PDU.FunctionCode == FCWriteSingleCoil && !frame.PDU.IsException && !isResponse {
			if frame.PDU.Value != CoilValueOff && frame.PDU.Value != CoilValueOn {
				return drop("LH-MODBUS-004",
					fmt.Sprintf("Invalid coil write value 0x%04X (must strictly be 0x0000 [OFF] or 0xFF00 [ON])", frame.PDU.Value))
			}
		}
	}

	// 2. Unit ID Zero Broadcast Check
	if fe.policy.BlockUnitIDZeroBroadcast && frame.MBAP.UnitID == 0 {
		return drop("LH-MODBUS-006", "Modbus broadcast Unit ID 0 is prohibited by firewall policy")
	}

	// 3. Unit ID Allowlist Check
	if fe.policy.UnitIDAllowlistEnabled && !fe.isUnitIDAllowed(frame.MBAP.UnitID) {
		return drop("LH-MODBUS-006",
			fmt.Sprintf("Unit ID %d is not in authorized slave allowlist", frame.MBAP.UnitID))
	}

	// 4. Rate Limiting Check
	if fe.policy.RateLimitingEnabled {
		limiter := fe.getLimiter(clientIP)
		if !limiter.Allow(now) {
			return drop("LH-MODBUS-007",
				fmt.Sprintf("Client IP %s exceeded polling rate limit (%d pps threshold)", clientIP, fe.policy.MaxRequestsPerSec))
		}
	}

	// 5. Block Diagnostic and Proprietary Function Codes
	if fe.policy.BlockDiagnosticAndProprietaryFCs {
		fc := frame.PDU.FunctionCode
		if fc == FCDiagnostic {
			subName := DiagnosticSubFunctionName(frame.PDU.SubFunction)
			return drop("LH-MODBUS-002",
				fmt.Sprintf("Diagnostic function code 0x08 blocked (%s)", subName))
		}
		if fc == FCUMAS {
			return drop("LH-MODBUS-002",
				"Schneider UMAS proprietary function code 0x5A blocked (CVE-2019-10953 PLC control exploit prevention)")
		}
		if fc == FCEncapsulatedInterface {
			return drop("LH-MODBUS-002",
				"Encapsulated Interface / Device ID query (FC 0x2B) blocked")
		}
		if (fc >= 65 && fc <= 72) || (fc >= 100 && fc <= 110) {
			return drop("LH-MODBUS-002",
				fmt.Sprintf("Vendor-proprietary user-defined function code 0x%02X blocked", fc))
		}
	}

	// 6. Whitelist Function Codes
	if !fe.isFunctionCodeAllowed(frame.PDU.FunctionCode) {
		return drop("LH-MODBUS-002",
			fmt.Sprintf("Function code 0x%02X is not authorized in allowed_function_codes policy", frame.PDU.FunctionCode))
	}

	// 7. Write Permissions & IP Allowlist
	if isWriteFunction(frame.PDU.FunctionCode) && !isResponse {
		if !fe.isClientAllowedToWrite(clientIP) {
			return drop("LH-MODBUS-001",
				fmt.Sprintf("Client IP %s is not authorized to issue write commands (%s)", clientIP, frame.PDU.FunctionName))
		}
	}

	// 8. Register Range Bounds, Setpoints, and Slew-Rate Guards
	if !isResponse && !frame.PDU.IsException {
		if frame.PDU.FunctionCode == FCWriteSingleRegister {
			if v := fe.evaluateRegisterWrite(frame.PDU.StartAddress, frame.PDU.Value); !v.Accepted {
				return v
			}
		} else if frame.PDU.FunctionCode == FCWriteMultipleRegisters {
			start := frame.PDU.StartAddress
			for i, val := range frame.PDU.RegisterValues {
				addr := start + uint16(i)
				if v := fe.evaluateRegisterWrite(addr, val); !v.Accepted {
					return v
				}
			}
		}
	}

	// 9. Stateful Transaction Tracking (Request / Response correlation)
	if fe.policy.StatefulTransactionTracking && frame.IsTCP {
		txKey := (uint32(frame.MBAP.UnitID) << 16) | uint32(frame.MBAP.TransactionID)
		fe.txMu.Lock()
		defer fe.txMu.Unlock()

		if !isResponse {
			// Record pending request
			fe.pendingRequests[txKey] = PendingTx{
				TransactionID: frame.MBAP.TransactionID,
				UnitID:        frame.MBAP.UnitID,
				FunctionCode:  frame.PDU.FunctionCode,
				ClientIP:      clientIP,
				SentAt:        now,
			}
		} else {
			// Response matching
			pending, exists := fe.pendingRequests[txKey]
			if !exists {
				return drop("LH-MODBUS-008",
					fmt.Sprintf("Unsolicited Modbus TCP response: no pending request found for Transaction ID %d (Unit ID %d)",
						frame.MBAP.TransactionID, frame.MBAP.UnitID))
			}
			// Verify matching Function Code
			expectedFC := pending.FunctionCode
			if frame.PDU.FunctionCode != expectedFC && frame.PDU.FunctionCode != (expectedFC|0x80) {
				return drop("LH-MODBUS-008",
					fmt.Sprintf("Transaction desynchronization: response FC 0x%02X does not match request FC 0x%02X for TxID %d",
						frame.PDU.FunctionCode, expectedFC, frame.MBAP.TransactionID))
			}
			delete(fe.pendingRequests, txKey)
		}
	}

	return verdict
}

// evaluateRegisterWrite validates an individual register write against policy bounds.
func (fe *FirewallEngine) evaluateRegisterWrite(address, value uint16) DPIVerdict {
	verdict := DPIVerdict{Accepted: true, Action: "ACCEPT"}
	rule := fe.findRegisterRule(address)

	if rule == nil {
		if fe.policy.EnforceRegisterAddressBounds && len(fe.policy.RegisterRules) > 0 {
			verdict.Accepted = false
			verdict.Action = "DROP"
			verdict.RuleID = "LH-MODBUS-005"
			verdict.Reasons = []string{fmt.Sprintf("Write target register %d is outside configured allowed register addresses", address)}
			return verdict
		}
		return verdict
	}

	// Check Read-Only restriction
	if rule.ReadOnly {
		verdict.Accepted = false
		verdict.Action = "DROP"
		verdict.RuleID = "LH-MODBUS-005"
		name := rule.Name
		if name == "" {
			name = fmt.Sprintf("Register-%d", address)
		}
		verdict.Reasons = []string{fmt.Sprintf("Unauthorized write to read-only register %d (%s)", address, name)}
		return verdict
	}

	// Check Setpoint Value Limits
	if fe.policy.EnforceSetpointValueLimits {
		if rule.MinValue != nil && value < *rule.MinValue {
			verdict.Accepted = false
			verdict.Action = "DROP"
			verdict.RuleID = "LH-MODBUS-005"
			verdict.Reasons = []string{fmt.Sprintf("Register %d value %d is below configured minimum threshold %d", address, value, *rule.MinValue)}
			return verdict
		}
		if rule.MaxValue != nil && value > *rule.MaxValue {
			verdict.Accepted = false
			verdict.Action = "DROP"
			verdict.RuleID = "LH-MODBUS-005"
			verdict.Reasons = []string{fmt.Sprintf("Register %d value %d exceeds configured maximum threshold %d", address, value, *rule.MaxValue)}
			return verdict
		}
	}

	// Check Slew-Rate Guard
	if fe.policy.RegisterSlewRateGuard && rule.MaxSlewRate != nil {
		fe.regStateMu.Lock()
		defer fe.regStateMu.Unlock()

		prevVal, hasPrev := fe.registerStates[address]
		if hasPrev {
			diff := int32(value) - int32(prevVal)
			if diff < 0 {
				diff = -diff
			}
			maxSlew := int32(*rule.MaxSlewRate)
			if diff > maxSlew {
				verdict.Accepted = false
				verdict.Action = "DROP"
				verdict.RuleID = "LH-MODBUS-009"
				verdict.Reasons = []string{fmt.Sprintf("Register %d slew rate exceeded: step change %d exceeds limit of %d (previous: %d, target: %d)",
					address, diff, maxSlew, prevVal, value)}
				return verdict
			}
		}
		fe.registerStates[address] = value
	} else {
		fe.regStateMu.Lock()
		fe.registerStates[address] = value
		fe.regStateMu.Unlock()
	}

	return verdict
}
