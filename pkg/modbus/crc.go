package modbus

import (
	"encoding/binary"
	"fmt"
)

// ModbusRTUPolynomial is the standard reflected CRC-16 polynomial 0xA001 (x^16 + x^15 + x^2 + 1).
const ModbusRTUPolynomial uint16 = 0xA001

// ModbusRTUInitialValue is the standard seed 0xFFFF for Modbus RTU CRC calculation.
const ModbusRTUInitialValue uint16 = 0xFFFF

// ComputeCRC16 calculates the standard 16-bit cyclic redundancy check for Modbus RTU frames.
// It iterates through each byte, XORing into the lower byte of the 16-bit register and shifting
// right 8 times, applying the 0xA001 polynomial when the LSB is set.
func ComputeCRC16(data []byte) uint16 {
	crc := ModbusRTUInitialValue
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if (crc & 0x0001) != 0 {
				crc = (crc >> 1) ^ ModbusRTUPolynomial
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// AppendCRC16 appends the calculated CRC-16 checksum to data in little-endian order (low byte first).
func AppendCRC16(data []byte) []byte {
	crc := ComputeCRC16(data)
	res := make([]byte, len(data)+2)
	copy(res, data)
	res[len(data)] = byte(crc & 0xFF)
	res[len(data)+1] = byte((crc >> 8) & 0xFF)
	return res
}

// ValidateRTUCRC checks if the last 2 bytes of an RTU frame match the computed CRC of preceding bytes.
func ValidateRTUCRC(frame []byte) (bool, uint16, uint16) {
	if len(frame) < 3 {
		return false, 0, 0
	}
	payload := frame[:len(frame)-2]
	expectedCRC := binary.LittleEndian.Uint16(frame[len(frame)-2:])
	actualCRC := ComputeCRC16(payload)
	return actualCRC == expectedCRC, actualCRC, expectedCRC
}

// FormatCRC returns the CRC16 in standard hex notation (e.g. "0x4B12 (Wire: 12 4B)").
func FormatCRC(crc uint16) string {
	low := byte(crc & 0xFF)
	high := byte((crc >> 8) & 0xFF)
	return fmt.Sprintf("0x%04X (Wire: %02X %02X)", crc, low, high)
}
