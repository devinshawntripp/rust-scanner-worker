package model

type ProgressEvent struct {
	Stage  string `json:"stage"`
	Detail string `json:"detail"`
	TS     string `json:"ts"`
}

type Summary struct {
	Total     int `json:"total_findings"`
	Critical  int `json:"critical"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
}
