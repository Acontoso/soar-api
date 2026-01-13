package models

import (
	"net/http"
	"time"
)

type ClientAbuseIPRequestPayload struct {
	IP         string `json:"ip" validate:"required"`
	IncidentID string `json:"incident_id" validate:"required"`
}

type ClientAbuseIPResponsePayload struct {
	Confidence  string `json:"confidence"`
	Country     string `json:"country"`
	ReportCount int    `json:"report_count"`
	TOR         bool   `json:"tor"`
	Private     bool   `json:"private"`
	IOC         string `json:"ioc"`
}

// AbuseIPDBClient wraps HTTP access to the AbuseIPDB API with timeouts.
type AbuseIPDBClient struct {
	HTTP    *http.Client
	BaseURL string
	Timeout time.Duration
}

// AbuseIPDBResponse models the subset of fields we care about.
type AbuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryName          string `json:"countryName"`
		TotalReports         int    `json:"totalReports"`
		IsTor                bool   `json:"isTor"`
		CountryCode          string `json:"countryCode"`
		Usage                string `json:"usageType"`
	} `json:"data"`
}
