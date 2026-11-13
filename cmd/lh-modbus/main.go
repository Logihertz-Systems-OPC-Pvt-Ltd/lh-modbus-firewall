package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-modbus-firewall/pkg/modbus"
)

const (
	Version   = "v0.1.0"
	ToolName  = "lh-modbus"
	AuthorOrg = "Logihertz Systems (OPC) Private Limited"
)

func printUsage() {
	fmt.Printf(`%s %s - Industrial Modbus TCP DPI Firewall & Security Posture Auditor
Author: Sameer Tawade | %s (https://logihertz.com/)

USAGE:
  %s <command> [arguments...]

COMMANDS:
  scan          Audit firewall policy against 10 OT/SCADA security posture rules
  inspect-frame Deep packet inspection of a raw Modbus TCP or RTU hex frame
  filter-trace  Simulate and evaluate a series of Modbus frames against firewall policy
  crc16         Compute standard Modbus RTU CRC-16 checksum for raw hex data
  version       Print tool version and copyright information
  help          Display this help message

GLOBAL FLAGS:
  -v, --version Display version and exit
  -h, --help    Display usage instructions

COMMAND EXAMPLES:
  # Audit policy against 10 posture rules
  %s scan --format=table fixtures/hardened_modbus_policy.json
  %s scan --format=sarif --output=report.sarif fixtures/vulnerable_modbus_policy.json

  # Inspect a raw Modbus TCP frame
  %s inspect-frame 00010000000601030000000A
  %s inspect-frame --format=json 00020000000601050001FF00

  # Inspect a Modbus RTU serial frame with CRC
  %s inspect-frame 01030000000AC5CD

  # Evaluate a packet trace
  %s filter-trace fixtures/hardened_modbus_policy.json fixtures/sample_modbus_trace.json

  # Compute Modbus RTU CRC-16
  %s crc16 01030000000A

EXIT CODES:
  0  Success / Compliant (100/100 score, zero anomalies, zero dropped frames)
  1  Security finding detected / Frame dropped / Posture score < 100
  2  Invalid command-line syntax, missing arguments, or file read error
`, ToolName, Version, AuthorOrg, ToolName, ToolName, ToolName, ToolName, ToolName, ToolName, ToolName, ToolName)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	cmd := os.Args[1]

	switch cmd {
	case "-v", "--version", "version":
		fmt.Printf("%s %s (%s)\n", ToolName, Version, AuthorOrg)
		os.Exit(0)
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	case "scan":
		handleScan(os.Args[2:])
	case "inspect-frame":
		handleInspectFrame(os.Args[2:])
	case "filter-trace":
		handleFilterTrace(os.Args[2:])
	case "crc16":
		handleCRC16(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func handleScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "table", "Output format: table, json, sarif")
	output := fs.String("output", "", "Optional output file path")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintf(os.Stderr, "Error: missing required policy JSON file argument\nUsage: %s scan [flags] <policy.json>\n", ToolName)
		os.Exit(2)
	}

	policyPath := remaining[0]
	data, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read policy file %q: %v\n", policyPath, err)
		os.Exit(2)
	}

	var policy modbus.FirewallPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid policy JSON in %q: %v\n", policyPath, err)
		os.Exit(2)
	}

	if policy.Name == "" {
		policy.Name = policyPath
	}

	report := modbus.AuditPolicy(&policy)

	var outStr string
	switch strings.ToLower(*format) {
	case "table":
		outStr = modbus.RenderAuditTable(report)
	case "json":
		jsonStr, err := modbus.ToJSON(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing JSON: %v\n", err)
			os.Exit(2)
		}
		outStr = jsonStr + "\n"
	case "sarif":
		sarifStr, err := modbus.ToSARIF(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing SARIF: %v\n", err)
			os.Exit(2)
		}
		outStr = sarifStr + "\n"
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported output format %q (allowed: table, json, sarif)\n", *format)
		os.Exit(2)
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(outStr), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to write output to %q: %v\n", *output, err)
			os.Exit(2)
		}
	} else {
		fmt.Print(outStr)
	}

	if report.Score < 100 {
		os.Exit(1)
	}
	os.Exit(0)
}

func handleInspectFrame(args []string) {
	fs := flag.NewFlagSet("inspect-frame", flag.ContinueOnError)
	format := fs.String("format", "table", "Output format: table, json")
	output := fs.String("output", "", "Optional output file path")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintf(os.Stderr, "Error: missing required hex frame argument\nUsage: %s inspect-frame [flags] <hex-string>\n", ToolName)
		os.Exit(2)
	}

	hexData := remaining[0]
	frame, err := modbus.ParseHexFrame(hexData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing frame: %v\n", err)
		os.Exit(2)
	}

	var outStr string
	switch strings.ToLower(*format) {
	case "table":
		outStr = modbus.RenderFrameTable(frame)
	case "json":
		jsonStr, err := modbus.ToJSON(frame)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing frame JSON: %v\n", err)
			os.Exit(2)
		}
		outStr = jsonStr + "\n"
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported output format %q (allowed: table, json)\n", *format)
		os.Exit(2)
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(outStr), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to write output to %q: %v\n", *output, err)
			os.Exit(2)
		}
	} else {
		fmt.Print(outStr)
	}

	if len(frame.Anomalies) > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func handleFilterTrace(args []string) {
	fs := flag.NewFlagSet("filter-trace", flag.ContinueOnError)
	format := fs.String("format", "table", "Output format: table, json, sarif")
	output := fs.String("output", "", "Optional output file path")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	remaining := fs.Args()
	if len(remaining) < 2 {
		fmt.Fprintf(os.Stderr, "Error: missing arguments\nUsage: %s filter-trace [flags] <policy.json> <trace.json>\n", ToolName)
		os.Exit(2)
	}

	policyPath := remaining[0]
	tracePath := remaining[1]

	polData, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read policy file %q: %v\n", policyPath, err)
		os.Exit(2)
	}

	var policy modbus.FirewallPolicy
	if err := json.Unmarshal(polData, &policy); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid policy JSON: %v\n", err)
		os.Exit(2)
	}

	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read trace file %q: %v\n", tracePath, err)
		os.Exit(2)
	}

	var packets []modbus.TracePacket
	if err := json.Unmarshal(traceData, &packets); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid trace JSON: %v\n", err)
		os.Exit(2)
	}

	engine := modbus.NewFirewallEngine(&policy)
	result := &modbus.TraceResult{
		TotalPackets: len(packets),
		Evaluations:  make([]modbus.PacketEvaluation, 0, len(packets)),
		EvaluatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	for i, pkt := range packets {
		frame, err := modbus.ParseHexFrame(pkt.HexData)
		if err != nil {
			// Record malformed packet as dropped
			eval := modbus.PacketEvaluation{
				Index:    i + 1,
				ClientIP: pkt.ClientIP,
				ServerIP: pkt.ServerIP,
				Verdict: modbus.DPIVerdict{
					Accepted:  false,
					Action:    "DROP",
					RuleID:    "LH-MODBUS-004",
					Reasons:   []string{fmt.Sprintf("Corrupt hex frame: %v", err)},
					Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				},
			}
			result.Evaluations = append(result.Evaluations, eval)
			result.DroppedPackets++
			continue
		}

		verdict := engine.EvaluatePacket(pkt.ClientIP, frame, pkt.IsResponse, time.Now())
		eval := modbus.PacketEvaluation{
			Index:    i + 1,
			ClientIP: pkt.ClientIP,
			ServerIP: pkt.ServerIP,
			Frame:    *frame,
			Verdict:  verdict,
		}
		result.Evaluations = append(result.Evaluations, eval)
		if verdict.Accepted {
			result.AcceptedPackets++
		} else {
			result.DroppedPackets++
		}
	}

	var outStr string
	switch strings.ToLower(*format) {
	case "table":
		outStr = modbus.RenderTraceTable(result)
	case "json":
		jsonStr, err := modbus.ToJSON(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing trace result: %v\n", err)
			os.Exit(2)
		}
		outStr = jsonStr + "\n"
	case "sarif":
		sarifStr, err := modbus.TraceToSARIF(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing SARIF: %v\n", err)
			os.Exit(2)
		}
		outStr = sarifStr + "\n"
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported output format %q (allowed: table, json, sarif)\n", *format)
		os.Exit(2)
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(outStr), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to write output to %q: %v\n", *output, err)
			os.Exit(2)
		}
	} else {
		fmt.Print(outStr)
	}

	if result.DroppedPackets > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func handleCRC16(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Error: missing hex string argument\nUsage: %s crc16 <hex-string>\n", ToolName)
		os.Exit(2)
	}

	cleaned := modbus.CleanHexString(args[0])
	data, err := hex.DecodeString(cleaned)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid hex string: %v\n", err)
		os.Exit(2)
	}

	crc := modbus.ComputeCRC16(data)
	low := byte(crc & 0xFF)
	high := byte((crc >> 8) & 0xFF)

	fmt.Printf("Input Hex : %s (%d bytes)\n", strings.ToUpper(cleaned), len(data))
	fmt.Printf("CRC-16    : 0x%04X\n", crc)
	fmt.Printf("Wire Bytes: %02X %02X (Little-Endian: Low Byte 0x%02X, High Byte 0x%02X)\n", low, high, low, high)
	os.Exit(0)
}
