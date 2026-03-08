package model

import "encoding/json"

// NdjsonLine represents a single line in NDJSON report output.
type NdjsonLine struct {
	Type string          `json:"type"` // "header", "finding", "file", "summary", "metadata"
	Data json.RawMessage `json:"data"`
	// Header fields (only when Type == "header")
	Scanner json.RawMessage `json:"scanner,omitempty"`
	Target  json.RawMessage `json:"target,omitempty"`
	// Metadata fields (only when Type == "metadata")
	ScanStatus      string `json:"scan_status,omitempty"`
	InventoryStatus string `json:"inventory_status,omitempty"`
	InventoryReason string `json:"inventory_reason,omitempty"`
}

type ScanReport struct {
	ScanStatus      string       `json:"scan_status"`
	InventoryStatus string       `json:"inventory_status"`
	InventoryReason string       `json:"inventory_reason"`
	Summary         Summary      `json:"summary"`
	Findings        []Finding    `json:"findings"`
	Files           []FileRow    `json:"files"`
	Packages        []PackageRow `json:"packages"`
}

type Finding struct {
	ID             string      `json:"id"`
	SourceIDs      []string    `json:"source_ids"`
	Package        *Pkg        `json:"package"`
	ConfidenceTier string      `json:"confidence_tier"`
	EvidenceSource string      `json:"evidence_source"`
	AccuracyNote   string      `json:"accuracy_note"`
	Fixed          *bool       `json:"fixed"`
	FixedIn        string      `json:"fixed_in"`
	Recommendation string      `json:"recommendation"`
	Severity       string      `json:"severity"`
	CVSS           *CVSS       `json:"cvss"`
	Description    string      `json:"description"`
	Evidence       []Evidence  `json:"evidence"`
	References     []Reference `json:"references"`
	Confidence     string      `json:"confidence,omitempty"`
	EPSSScore      *float64    `json:"epss_score,omitempty"`
	EPSSPercentile *float64    `json:"epss_percentile,omitempty"`
	InKEV          *bool       `json:"in_kev,omitempty"`
}

type Pkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Version   string `json:"version"`
}

type CVSS struct {
	Base   float64 `json:"base"`
	Vector string  `json:"vector"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Evidence struct {
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type FileRow struct {
	Path       string `json:"path"`
	EntryType  string `json:"entry_type"`
	SizeBytes  *int64 `json:"size_bytes"`
	Mode       string `json:"mode"`
	MTime      string `json:"mtime"`
	SHA256     string `json:"sha256"`
	ParentPath string `json:"parent_path"`
}

type PackageRow struct {
	Name           string `json:"name"`
	Ecosystem      string `json:"ecosystem"`
	Version        string `json:"version"`
	SourceKind     string `json:"source_kind"`
	SourcePath     string `json:"source_path"`
	ConfidenceTier string `json:"confidence_tier"`
	EvidenceSource string `json:"evidence_source"`
}
