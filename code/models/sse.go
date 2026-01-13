package models

type SSEUploadRequestPayload struct {
	IOC        string `json:"ioc" validate:"required"`
	IncidentID string `json:"incident_id" validate:"required"`
}

type SSEUploadResponsePayload struct {
	Added       bool   `json:"added"`
	IOC         string `json:"ioc"`
	Integration string `json:"integration"`
	Action      string `json:"action"`
}

type ZscalerAddPayload struct {
	Addresses []string `json:"addresses"`
	Type      string   `json:"type,omitempty"`
	Name      string   `json:"name,omitempty"`
}
