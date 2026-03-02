package model

import "encoding/json"

type ProgressEvent struct {
	Stage    string          `json:"stage"`
	Detail   string          `json:"detail"`
	TS       string          `json:"ts"`
	Pct      *int            `json:"pct,omitempty"`
	Pipeline json.RawMessage `json:"pipeline,omitempty"`
}

type Summary struct {
	Total     int `json:"total_findings"`
	Critical  int `json:"critical"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
}
