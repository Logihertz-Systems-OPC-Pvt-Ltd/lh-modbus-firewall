package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// FunctionName maps a function code to its human-readable specification title.
func FunctionName(fc uint8) string {
	switch fc {
	case FCReadCoils:
		return "Read Coils (0x01)"
	case FCReadDiscreteInputs:
		return "Read Discrete Inputs (0x02)"
	case FCReadHoldingRegisters:
		return "Read Holding Registers (0x03)"
	case FCReadInputRegisters:
		return "Read Input Registers (0x04)"
	case FCWriteSingleCoil:
		return "Write Single Coil (0x05)"
	case FCWriteSingleRegister:
		return "Write Single Register (0x06)"
	case FCReadExceptionStatus:
		return "Read Exception Status (0x07)"
	case FCDiagnostic:
		return "Diagnostic (0x08)"
	case FCGetCommEventCounter:
		return "Get Comm Event Counter (0x0B)"
	case FCGetCommEventLog:
		return "Get Comm Event Log (0x0C)"
	case FCWriteMultipleCoils:
		return "Write Multiple Coils (0x0F)"
	case FCWriteMultipleRegisters:
		return "Write Multiple Registers (0x10)"
	case FCReportServerID:
		return "Report Server ID (0x11)"
	case FCReadFileRecord:
		return "Read File Record (0x14)"
	case FCWriteFileRecord:
		return "Write File Record (0x15)"
	case FCMaskWriteRegister:
		return "Mask Write Register (0x16)"
	case FCReadWriteMultipleRegisters:
		return "Read/Write Multiple Registers (0x17)"
	case FCReadFIFOQueue:
		return "Read FIFO Queue (0x18)"
	case FCEncapsulatedInterface:
		return "Encapsulated Interface / Read Device ID (0x2B)"
	case FCUMAS:
		return "Schneider UMAS Proprietary Control (0x5A)"
	default:
		if (fc >= 65 && fc <= 72) || (fc >= 100 && fc <= 110) {
			return fmt.Sprintf("User-Defined / Vendor Function (0x%02X)", fc)
		}
		return fmt.Sprintf("Unknown Function Code (0x%02X)", fc)
	}
}

// ExceptionName maps a Modbus exception code to its standard title.
func ExceptionName(ec uint8) string {
	switch ec {
	case ExpIllegalFunction:
		return "Illegal Function (0x01)"
	case ExpIllegalDataAddress:
		return "Illegal Data Address (0x02)"
	case ExpIllegalDataValue:
		return "Illegal Data Value (0x03)"
	case ExpServerDeviceFailure:
		return "Server Device Failure (0x04)"
	case ExpAcknowledge:
		return "Acknowledge (0x05)"
	case ExpServerDeviceBusy:
		return "Server Device Busy (0x06)"
	case ExpMemoryParityError:
		return "Memory Parity Error (0x08)"
	case ExpGatewayPathUnavailable:
		return "Gateway Path Unavailable (0x0A)"
	case ExpGatewayTargetDeviceFail:
		return "Gateway Target Device Failed (0x0B)"
	default:
		return fmt.Sprintf("Unknown Exception Code (0x%02X)", ec)
	}
}

// DiagnosticSubFunctionName returns the descriptive title for an FC 08 sub-function.
func DiagnosticSubFunctionName(sub uint16) string {
	switch sub {
	case SubFCReturnQueryData:
		return "Return Query Data (Echo 0x0000)"
	case SubFCRestartCommunicationsOption:
		return "Restart Communications Option (0x0001)"
	case SubFCReturnDiagnosticRegister:
		return "Return Diagnostic Register (0x0002)"
	case SubFCChangeAsciiInputDelimiter:
		return "Change ASCII Input Delimiter (0x0003)"
	case SubFCForceListenOnlyMode:
		return "Force Listen Only Mode (0x0004)"
	case SubFCClearCountersAndDiagRegister:
		return "Clear Counters and Diagnostic Register (0x000A)"
	case SubFCReturnBusMessageCount:
		return "Return Bus Message Count (0x000B)"
	case SubFCReturnBusCommErrorCount:
		return "Return Bus Comm Error Count (0x000C)"
	case SubFCReturnBusExceptionErrorCount:
		return "Return Bus Exception Error Count (0x000D)"
	case SubFCReturnServerMessageCount:
		return "Return Server Message Count (0x000E)"
	case SubFCReturnServerNoResponseCount:
		return "Return Server No Response Count (0x000F)"
	case SubFCReturnServerNAKCount:
		return "Return Server NAK Count (0x0010)"
	case SubFCReturnServerBusyCount:
		return "Return Server Busy Count (0x0011)"
	case SubFCReturnBusCharacterOverrunCnt:
		return "Return Bus Character Overrun Count (0x0012)"
	case SubFCClearOverrunCounterAndFlag:
		return "Clear Overrun Counter and Flag (0x0014)"
	default:
		return fmt.Sprintf("Diagnostic Sub-Function (0x%04X)", sub)
	}
}

// DissectTCP parses a Modbus TCP frame containing a 7-byte MBAP header and PDU.
func DissectTCP(data []byte) (*ModbusFrame, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("frame too short for Modbus TCP MBAP header: %d bytes (minimum 7)", len(data))
	}

	frame := &ModbusFrame{
		WireLen:   len(data),
		RawBytes:  data,
		IsTCP:     true,
		Anomalies: make([]string, 0),
	}

	frame.MBAP.TransactionID = binary.BigEndian.Uint16(data[0:2])
	frame.MBAP.ProtocolID = binary.BigEndian.Uint16(data[2:4])
	frame.MBAP.Length = binary.BigEndian.Uint16(data[4:6])
	frame.MBAP.UnitID = data[6]

	// Protocol ID Check
	if frame.MBAP.ProtocolID != 0x0000 {
		frame.Anomalies = append(frame.Anomalies,
			fmt.Sprintf("Non-zero Modbus TCP Protocol ID: 0x%04X (expected 0x0000)", frame.MBAP.ProtocolID))
	}

	// Length range check
	if frame.MBAP.Length < 2 || frame.MBAP.Length > 254 {
		frame.Anomalies = append(frame.Anomalies,
			fmt.Sprintf("Invalid MBAP Length field: %d (standard range 2..254)", frame.MBAP.Length))
	}

	// Wire length alignment check: WireLen must equal 6 + MBAP.Length
	expectedWireLen := 6 + int(frame.MBAP.Length)
	if len(data) != expectedWireLen {
		frame.Anomalies = append(frame.Anomalies,
			fmt.Sprintf("MBAP length mismatch: actual wire length %d bytes, MBAP header declared %d bytes (expected wire length %d)",
				len(data), frame.MBAP.Length, expectedWireLen))
	}

	// Broadcast check
	if frame.MBAP.UnitID == 0 {
		frame.Anomalies = append(frame.Anomalies, "Unit ID is 0 (broadcast address)")
	}

	pduBytes := data[7:]
	if len(pduBytes) == 0 {
		frame.Anomalies = append(frame.Anomalies, "Missing Modbus PDU payload")
		return frame, nil
	}

	dissectPDU(pduBytes, &frame.PDU, &frame.Anomalies)
	return frame, nil
}

// DissectRTU parses a Modbus RTU serial frame consisting of Unit ID, PDU, and 2-byte CRC16.
func DissectRTU(data []byte) (*ModbusFrame, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("frame too short for Modbus RTU: %d bytes (minimum 4)", len(data))
	}

	frame := &ModbusFrame{
		WireLen:   len(data),
		RawBytes:  data,
		IsTCP:     false,
		Anomalies: make([]string, 0),
	}

	ok, actualCRC, expectedCRC := ValidateRTUCRC(data)
	frame.CRC16 = actualCRC
	frame.CRCOk = ok
	if !ok {
		frame.Anomalies = append(frame.Anomalies,
			fmt.Sprintf("CRC-16 mismatch: frame has 0x%04X but calculated 0x%04X", expectedCRC, actualCRC))
	}

	frame.MBAP.UnitID = data[0]
	if frame.MBAP.UnitID == 0 {
		frame.Anomalies = append(frame.Anomalies, "Unit ID is 0 (broadcast address)")
	}

	pduBytes := data[1 : len(data)-2]
	if len(pduBytes) == 0 {
		frame.Anomalies = append(frame.Anomalies, "Missing Modbus RTU PDU payload")
		return frame, nil
	}

	dissectPDU(pduBytes, &frame.PDU, &frame.Anomalies)
	return frame, nil
}

func dissectPDU(pduBytes []byte, pdu *ModbusPDU, anomalies *[]string) {
	rawFC := pduBytes[0]
	pdu.RawPayload = pduBytes

	// Check if this is an Exception response
	if (rawFC & 0x80) != 0 {
		pdu.IsException = true
		pdu.FunctionCode = rawFC & 0x7F
		pdu.FunctionName = FunctionName(pdu.FunctionCode)
		if len(pduBytes) >= 2 {
			pdu.ExceptionCode = pduBytes[1]
			pdu.ExceptionName = ExceptionName(pdu.ExceptionCode)
		} else {
			*anomalies = append(*anomalies, "Truncated Modbus exception response: missing exception code")
		}
		*anomalies = append(*anomalies,
			fmt.Sprintf("Modbus Exception Response for %s: %s", pdu.FunctionName, pdu.ExceptionName))
		return
	}

	pdu.FunctionCode = rawFC
	pdu.FunctionName = FunctionName(pdu.FunctionCode)

	switch pdu.FunctionCode {
	case FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters, FCReadInputRegisters:
		if len(pduBytes) >= 5 {
			pdu.StartAddress = binary.BigEndian.Uint16(pduBytes[1:3])
			pdu.Quantity = binary.BigEndian.Uint16(pduBytes[3:5])

			// Sanity check quantities
			if (pdu.FunctionCode == FCReadCoils || pdu.FunctionCode == FCReadDiscreteInputs) && (pdu.Quantity < 1 || pdu.Quantity > 2000) {
				*anomalies = append(*anomalies,
					fmt.Sprintf("Invalid bit read quantity: %d (allowed 1..2000)", pdu.Quantity))
			} else if (pdu.FunctionCode == FCReadHoldingRegisters || pdu.FunctionCode == FCReadInputRegisters) && (pdu.Quantity < 1 || pdu.Quantity > 125) {
				*anomalies = append(*anomalies,
					fmt.Sprintf("Invalid register read quantity: %d (allowed 1..125)", pdu.Quantity))
			}
		} else if len(pduBytes) >= 2 {
			// Response payload
			pdu.ByteCount = pduBytes[1]
			if pdu.FunctionCode == FCReadHoldingRegisters || pdu.FunctionCode == FCReadInputRegisters {
				count := int(pdu.ByteCount) / 2
				pdu.RegisterValues = make([]uint16, 0, count)
				for i := 0; i < count && (2+i*2+2) <= len(pduBytes); i++ {
					val := binary.BigEndian.Uint16(pduBytes[2+i*2 : 2+i*2+2])
					pdu.RegisterValues = append(pdu.RegisterValues, val)
				}
			}
		}

	case FCWriteSingleCoil:
		if len(pduBytes) >= 5 {
			pdu.StartAddress = binary.BigEndian.Uint16(pduBytes[1:3])
			pdu.Value = binary.BigEndian.Uint16(pduBytes[3:5])
			// Strictly 0x0000 or 0xFF00
			if pdu.Value != CoilValueOff && pdu.Value != CoilValueOn {
				*anomalies = append(*anomalies,
					fmt.Sprintf("Malformed coil write value: 0x%04X (must strictly be 0x0000 [OFF] or 0xFF00 [ON])", pdu.Value))
			}
		} else {
			*anomalies = append(*anomalies, "Truncated Write Single Coil request")
		}

	case FCWriteSingleRegister:
		if len(pduBytes) >= 5 {
			pdu.StartAddress = binary.BigEndian.Uint16(pduBytes[1:3])
			pdu.Value = binary.BigEndian.Uint16(pduBytes[3:5])
		} else {
			*anomalies = append(*anomalies, "Truncated Write Single Register request")
		}

	case FCWriteMultipleCoils:
		if len(pduBytes) >= 6 {
			pdu.StartAddress = binary.BigEndian.Uint16(pduBytes[1:3])
			pdu.Quantity = binary.BigEndian.Uint16(pduBytes[3:5])
			pdu.ByteCount = pduBytes[5]
			expectedBytes := int((pdu.Quantity + 7) / 8)
			if int(pdu.ByteCount) != expectedBytes {
				*anomalies = append(*anomalies,
					fmt.Sprintf("WriteMultipleCoils byte count mismatch: %d bytes for %d coils (expected %d)",
						pdu.ByteCount, pdu.Quantity, expectedBytes))
			}
		} else {
			*anomalies = append(*anomalies, "Truncated Write Multiple Coils request")
		}

	case FCWriteMultipleRegisters:
		if len(pduBytes) >= 6 {
			pdu.StartAddress = binary.BigEndian.Uint16(pduBytes[1:3])
			pdu.Quantity = binary.BigEndian.Uint16(pduBytes[3:5])
			pdu.ByteCount = pduBytes[5]
			expectedBytes := int(pdu.Quantity * 2)
			if int(pdu.ByteCount) != expectedBytes {
				*anomalies = append(*anomalies,
					fmt.Sprintf("WriteMultipleRegisters byte count mismatch: %d bytes for %d registers (expected %d)",
						pdu.ByteCount, pdu.Quantity, expectedBytes))
			}
			dataLen := len(pduBytes) - 6
			regCount := dataLen / 2
			pdu.RegisterValues = make([]uint16, 0, regCount)
			for i := 0; i < regCount; i++ {
				offset := 6 + i*2
				if offset+2 <= len(pduBytes) {
					pdu.RegisterValues = append(pdu.RegisterValues, binary.BigEndian.Uint16(pduBytes[offset:offset+2]))
				}
			}
		} else {
			*anomalies = append(*anomalies, "Truncated Write Multiple Registers request")
		}

	case FCMaskWriteRegister:
		if len(pduBytes) >= 7 {
			pdu.StartAddress = binary.BigEndian.Uint16(pduBytes[1:3])
		}

	case FCReadWriteMultipleRegisters:
		if len(pduBytes) >= 9 {
			pdu.StartAddress = binary.BigEndian.Uint16(pduBytes[1:3])
			pdu.Quantity = binary.BigEndian.Uint16(pduBytes[3:5])
		}

	case FCDiagnostic:
		if len(pduBytes) >= 3 {
			pdu.SubFunction = binary.BigEndian.Uint16(pduBytes[1:3])
			subName := DiagnosticSubFunctionName(pdu.SubFunction)
			*anomalies = append(*anomalies,
				fmt.Sprintf("Diagnostic Function 0x08 invoked: %s", subName))
		}

	case FCEncapsulatedInterface:
		*anomalies = append(*anomalies, "Encapsulated Interface / Device ID query (FC 0x2B)")

	case FCUMAS:
		*anomalies = append(*anomalies, "Dangerous Schneider UMAS proprietary function code 0x5A detected (CVE-2019-10953 risk)")

	default:
		if (pdu.FunctionCode >= 65 && pdu.FunctionCode <= 72) || (pdu.FunctionCode >= 100 && pdu.FunctionCode <= 110) {
			*anomalies = append(*anomalies,
				fmt.Sprintf("User-defined / vendor-proprietary function code 0x%02X detected", pdu.FunctionCode))
		}
	}
}

// CleanHexString strips whitespace, colons, commas, and 0x prefixes from a hex string.
func CleanHexString(hexStr string) string {
	s := strings.TrimSpace(hexStr)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, "0X", "")
	return s
}

// ParseHexFrame parses a raw hex string into a ModbusFrame, detecting TCP or RTU automatically.
func ParseHexFrame(hexStr string) (*ModbusFrame, error) {
	cleaned := CleanHexString(hexStr)
	data, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid hexadecimal data: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty hexadecimal frame")
	}

	// 1. Check if the frame passes Modbus RTU CRC-16 validation
	if len(data) >= 4 {
		if ok, _, _ := ValidateRTUCRC(data); ok {
			return DissectRTU(data)
		}
	}

	// 2. Check if the frame matches Modbus TCP MBAP structure:
	// Protocol ID (bytes 2..3) == 0x0000 and WireLen == 6 + MBAP.Length
	if len(data) >= 7 && data[2] == 0x00 && data[3] == 0x00 {
		mbapLen := binary.BigEndian.Uint16(data[4:6])
		if len(data) == 6+int(mbapLen) {
			return DissectTCP(data)
		}
	}

	// 3. Fallback: if len >= 7, parse as TCP; otherwise as RTU
	if len(data) >= 7 {
		return DissectTCP(data)
	}

	return DissectRTU(data)
}
