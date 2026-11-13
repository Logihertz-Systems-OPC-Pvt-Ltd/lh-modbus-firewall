package modbus

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ANSI color codes for terminal rendering.
const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
)

// ToJSON serializes any data structure to indented JSON.
func ToJSON(v interface{}) (string, error) {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// RenderAuditTable formats an AuditReport as an ANSI colorized terminal table.
func RenderAuditTable(report *AuditReport) string {
	var sb strings.Builder

	scoreColor := ColorRed
	if report.Score == 100 {
		scoreColor = ColorGreen
	} else if report.Score >= 85 {
		scoreColor = ColorYellow
	}

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s================================================================================%s\n", ColorBold, ColorReset))
	sb.WriteString(fmt.Sprintf("%s   LOGIHERTZ MODBUS TCP FIREWALL POSTURE AUDIT REPORT%s\n", ColorBold+ColorCyan, ColorReset))
	sb.WriteString(fmt.Sprintf("%s================================================================================%s\n", ColorBold, ColorReset))
	sb.WriteString(fmt.Sprintf(" Policy Name  : %s%s%s\n", ColorBold, report.PolicyName, ColorReset))
	sb.WriteString(fmt.Sprintf(" Overall Score: %s%s%d / 100 [%s]%s\n", ColorBold, scoreColor, report.Score, report.Status, ColorReset))
	sb.WriteString(fmt.Sprintf(" Rules Checked: %d Total | %s%d Passed%s | %s%d Failed%s\n",
		report.TotalRules, ColorGreen, report.PassedRules, ColorReset, ColorRed, report.FailedRules, ColorReset))
	sb.WriteString(fmt.Sprintf(" Audited At   : %s\n", report.AuditedAt))
	sb.WriteString(fmt.Sprintf("--------------------------------------------------------------------------------\n"))

	if len(report.Findings) == 0 {
		sb.WriteString(fmt.Sprintf("\n %s✓ ZERO POSTURE DEFECTS DETECTED. POLICY FULLY HARDENED.%s\n\n", ColorGreen+ColorBold, ColorReset))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("\n%sIDENTIFIED DEFECTS & FINDINGS:%s\n\n", ColorBold+ColorRed, ColorReset))
	for i, f := range report.Findings {
		sevColor := ColorRed
		if f.Severity == SeverityHigh {
			sevColor = ColorMagenta
		} else if f.Severity == SeverityMedium {
			sevColor = ColorYellow
		} else if f.Severity == SeverityLow {
			sevColor = ColorBlue
		}

		sb.WriteString(fmt.Sprintf(" %d. %s[%s]%s %s%s%s (Deduction: -%d pts)\n",
			i+1, sevColor+ColorBold, f.Severity, ColorReset, ColorBold, f.Title, ColorReset, f.Weight))
		sb.WriteString(fmt.Sprintf("    Rule ID    : %s\n", f.RuleID))
		sb.WriteString(fmt.Sprintf("    CWE        : %s\n", f.CWE))
		sb.WriteString(fmt.Sprintf("    Description: %s\n", f.Description))
		sb.WriteString(fmt.Sprintf("    Remediation: %s%s%s\n\n", ColorCyan, f.Remediation, ColorReset))
	}

	return sb.String()
}

// RenderFrameTable formats a dissected ModbusFrame as an ANSI table.
func RenderFrameTable(frame *ModbusFrame) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s================================================================================%s\n", ColorBold, ColorReset))
	sb.WriteString(fmt.Sprintf("%s   MODBUS FRAME DEEP PACKET INSPECTION (DPI) DISSECTION%s\n", ColorBold+ColorCyan, ColorReset))
	sb.WriteString(fmt.Sprintf("%s================================================================================%s\n", ColorBold, ColorReset))

	if frame.IsTCP {
		sb.WriteString(fmt.Sprintf(" Transport    : %sModbus TCP (MBAP Encapsulated)%s\n", ColorBold+ColorGreen, ColorReset))
		sb.WriteString(fmt.Sprintf(" Tx ID        : 0x%04X (%d)\n", frame.MBAP.TransactionID, frame.MBAP.TransactionID))
		sb.WriteString(fmt.Sprintf(" Protocol ID  : 0x%04X\n", frame.MBAP.ProtocolID))
		sb.WriteString(fmt.Sprintf(" MBAP Length  : %d bytes (Wire Length: %d bytes)\n", frame.MBAP.Length, frame.WireLen))
		sb.WriteString(fmt.Sprintf(" Unit ID      : 0x%02X (%d)\n", frame.MBAP.UnitID, frame.MBAP.UnitID))
	} else {
		sb.WriteString(fmt.Sprintf(" Transport    : %sModbus RTU (Serial Framed)%s\n", ColorBold+ColorYellow, ColorReset))
		sb.WriteString(fmt.Sprintf(" Unit ID      : 0x%02X (%d)\n", frame.MBAP.UnitID, frame.MBAP.UnitID))
		crcColor := ColorGreen
		if !frame.CRCOk {
			crcColor = ColorRed
		}
		sb.WriteString(fmt.Sprintf(" CRC-16 Check : %s%s (Valid: %t)%s\n",
			crcColor, FormatCRC(frame.CRC16), frame.CRCOk, ColorReset))
	}

	sb.WriteString(fmt.Sprintf(" Function     : %s%s%s\n", ColorBold, frame.PDU.FunctionName, ColorReset))
	if frame.PDU.IsException {
		sb.WriteString(fmt.Sprintf(" Exception    : %s%s%s\n", ColorBold+ColorRed, frame.PDU.ExceptionName, ColorReset))
	} else {
		if frame.PDU.SubFunction != 0 || frame.PDU.FunctionCode == FCDiagnostic {
			sb.WriteString(fmt.Sprintf(" Sub-Function : 0x%04X (%s)\n", frame.PDU.SubFunction, DiagnosticSubFunctionName(frame.PDU.SubFunction)))
		}
		if frame.PDU.Quantity > 0 {
			sb.WriteString(fmt.Sprintf(" Start Address: %d (0x%04X)\n", frame.PDU.StartAddress, frame.PDU.StartAddress))
			sb.WriteString(fmt.Sprintf(" Quantity     : %d\n", frame.PDU.Quantity))
		} else if frame.PDU.FunctionCode == FCWriteSingleRegister || frame.PDU.FunctionCode == FCWriteSingleCoil {
			sb.WriteString(fmt.Sprintf(" Address      : %d (0x%04X)\n", frame.PDU.StartAddress, frame.PDU.StartAddress))
			sb.WriteString(fmt.Sprintf(" Value        : %d (0x%04X)\n", frame.PDU.Value, frame.PDU.Value))
		}
		if len(frame.PDU.RegisterValues) > 0 {
			sb.WriteString(fmt.Sprintf(" Registers    : %v\n", frame.PDU.RegisterValues))
		}
	}

	if len(frame.Anomalies) > 0 {
		sb.WriteString(fmt.Sprintf("--------------------------------------------------------------------------------\n"))
		sb.WriteString(fmt.Sprintf(" %sANOMALIES & INTEGRITY ALERTS:%s\n", ColorBold+ColorRed, ColorReset))
		for _, a := range frame.Anomalies {
			sb.WriteString(fmt.Sprintf("  • %s%s%s\n", ColorRed, a, ColorReset))
		}
	} else {
		sb.WriteString(fmt.Sprintf("--------------------------------------------------------------------------------\n"))
		sb.WriteString(fmt.Sprintf(" %s✓ Frame conforms to standard Modbus protocol encoding%s\n", ColorGreen, ColorReset))
	}
	sb.WriteString("\n")

	return sb.String()
}

// RenderTraceTable formats the result of a packet trace evaluation as an ANSI table.
func RenderTraceTable(result *TraceResult) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s================================================================================%s\n", ColorBold, ColorReset))
	sb.WriteString(fmt.Sprintf("%s   MODBUS PACKET TRACE FIREWALL EVALUATION SUMMARY%s\n", ColorBold+ColorCyan, ColorReset))
	sb.WriteString(fmt.Sprintf("%s================================================================================%s\n", ColorBold, ColorReset))
	sb.WriteString(fmt.Sprintf(" Total Packets Evaluated: %d\n", result.TotalPackets))
	sb.WriteString(fmt.Sprintf(" Accepted Traffic       : %s%d%s\n", ColorGreen+ColorBold, result.AcceptedPackets, ColorReset))
	sb.WriteString(fmt.Sprintf(" Dropped / Blocked      : %s%d%s\n", ColorRed+ColorBold, result.DroppedPackets, ColorReset))
	sb.WriteString(fmt.Sprintf(" Evaluated At           : %s\n", result.EvaluatedAt))
	sb.WriteString(fmt.Sprintf("--------------------------------------------------------------------------------\n\n"))

	for _, ev := range result.Evaluations {
		actionColor := ColorGreen
		if !ev.Verdict.Accepted {
			actionColor = ColorRed
		}

		sb.WriteString(fmt.Sprintf(" [%03d] %s[%-6s]%s Client: %-15s | Unit: %-3d | FC: %-28s\n",
			ev.Index, actionColor+ColorBold, ev.Verdict.Action, ColorReset, ev.ClientIP, ev.Frame.MBAP.UnitID, ev.Frame.PDU.FunctionName))

		if !ev.Verdict.Accepted {
			sb.WriteString(fmt.Sprintf("       Rule   : %s%s%s\n", ColorBold+ColorRed, ev.Verdict.RuleID, ColorReset))
			for _, r := range ev.Verdict.Reasons {
				sb.WriteString(fmt.Sprintf("       Reason : %s%s%s\n", ColorRed, r, ColorReset))
			}
		}
	}
	sb.WriteString("\n")

	return sb.String()
}

// SARIF v2.1.0 JSON Structures
type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool      sarifTool       `json:"tool"`
	Results   []sarifResult   `json:"results"`
	Artifacts []sarifArtifact `json:"artifacts,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Help                 sarifText      `json:"help"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
}

type sarifPhysLoc struct {
	ArtifactLocation sarifArtLoc `json:"artifactLocation"`
}

type sarifArtLoc struct {
	URI string `json:"uri"`
}

type sarifArtifact struct {
	Location sarifArtLoc `json:"location"`
}

// ToSARIF converts an AuditReport into an OASIS SARIF v2.1.0 JSON document.
func ToSARIF(report *AuditReport) (string, error) {
	ruleMap := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(report.Findings))

	for _, f := range report.Findings {
		level := "error"
		if f.Severity == SeverityMedium {
			level = "warning"
		} else if f.Severity == SeverityLow {
			level = "note"
		}

		if _, exists := ruleMap[f.RuleID]; !exists {
			ruleMap[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Description},
				DefaultConfiguration: sarifConfig{
					Level: level,
				},
				Help: sarifText{Text: f.Remediation},
				Properties: map[string]any{
					"cwe":    f.CWE,
					"weight": f.Weight,
				},
			}
		}

		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   level,
			Message: sarifText{Text: fmt.Sprintf("%s - %s", f.Title, f.Description)},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysLoc{
						ArtifactLocation: sarifArtLoc{
							URI: report.PolicyName,
						},
					},
				},
			},
		})
	}

	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	doc := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "lh-modbus",
						Version:        "0.1.0",
						InformationURI: "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-modbus-firewall",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	bytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// TraceToSARIF converts dropped trace evaluations into an OASIS SARIF v2.1.0 JSON document.
func TraceToSARIF(result *TraceResult) (string, error) {
	results := make([]sarifResult, 0)

	for _, ev := range result.Evaluations {
		if !ev.Verdict.Accepted {
			reasons := strings.Join(ev.Verdict.Reasons, "; ")
			results = append(results, sarifResult{
				RuleID:  ev.Verdict.RuleID,
				Level:   "error",
				Message: sarifText{Text: fmt.Sprintf("Packet #%d from %s dropped: %s", ev.Index, ev.ClientIP, reasons)},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysLoc{
							ArtifactLocation: sarifArtLoc{
								URI: fmt.Sprintf("trace-packet-%d", ev.Index),
							},
						},
					},
				},
			})
		}
	}

	doc := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "lh-modbus",
						Version:        "0.1.0",
						InformationURI: "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-modbus-firewall",
					},
				},
				Results: results,
			},
		},
	}

	bytes, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
