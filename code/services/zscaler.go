package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Acontoso/soar-api/code/models"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

var ZSCALER_SOAR_FQDN_LIST string = "9980445"
var ZSCALER_SOAR_IP_LIST string = "9980441"
var SCOPE string = "api://6c96f6a7-8e7a-4dd5-8a2b-46bf6100a3bd/.default"

// AbuseIPDBClient wraps HTTP access to the AbuseIPDB API with timeouts.
type ZscalerClient struct {
	HTTP    *http.Client
	BaseURL string
	Timeout time.Duration
}

// NewZscalerClient constructs a client with sensible defaults.
func NewZscalerClient() *ZscalerClient {
	return &ZscalerClient{
		HTTP:    &http.Client{Timeout: 5 * time.Second},
		BaseURL: "https://zsapi.zscalerthree.net/api/v1/ipDestinationGroups",
		Timeout: 5 * time.Second,
	}
}

type ZscalerResponse struct {
	Confidence int `json:"average_confidence"`
}

// BlockIOC queries Zscaler for a single IOC.
func (zscaler *ZscalerClient) BlockIOC(c *gin.Context, ioc string, ssmClient *ssm.Client, kmsClient *kms.Client, lg *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(c, zscaler.Timeout)
	defer cancel()
	if zscaler.HTTP == nil {
		zscaler.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	if zscaler.Timeout <= 0 {
		zscaler.Timeout = 5 * time.Second
	}
	if zscaler.BaseURL == "" {
		zscaler.BaseURL = "https://zsapi.zscalerthree.net/api/v1/ipDestinationGroups"
	}
	zscalerClientID, err := GetParam(c, ssmClient, kmsClient, "zscaler_client_id", lg)
	if err != nil {
		lg.Error("failed to get zscaler client id", "error", err)
		return false, err
	}
	zscalerClientSecret, err := GetParam(c, ssmClient, kmsClient, "zscaler_client_secret", lg)
	if err != nil {
		lg.Error("failed to get zscaler client secret", "error", err)
		return false, err
	}
	AzureADClient, err := NewAzureADClient(zscalerClientID, zscalerClientSecret, lg)
	if err != nil {
		lg.Error("failed to create AzureAD client", "error", err)
		return false, err
	}
	accessToken, err := AzureADClient.GetAccessTokenSecret(ctx, SCOPE)
	if err != nil {
		lg.Error("Failed to get access token from Azure AD", "error", err)
		return false, err
	}
	var reqURL string
	var body models.ZscalerAddPayload
	iocType := models.IOCClassifier(ioc)
	if iocType == "Domain" {
		list_id := ZSCALER_SOAR_FQDN_LIST
		reqURL = fmt.Sprintf("https://zsapi.zscalerthree.net/api/v1/ipDestinationGroups/%s", list_id)
		body = models.ZscalerAddPayload{
			Addresses: []string{ioc},
			Type:      "DSTN_FQDN",
			Name:      "SOAR Malicious Domain List",
		}
	}
	if iocType == "IPv4" || iocType == "IPv6" {
		list_id := ZSCALER_SOAR_IP_LIST
		reqURL = fmt.Sprintf("https://zsapi.zscalerthree.net/api/v1/ipDestinationGroups/%s", list_id)
		// Build JSON payload
		body = models.ZscalerAddPayload{
			Addresses: []string{ioc},
			Type:      "DSTN_IP",
			Name:      "SOAR Malicious IP Address List",
		}
	}

	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		lg.Error("failed to parse base url", "error", err)
		return false, err
	}
	q := parsedURL.Query()
	q.Set("override", "false")
	parsedURL.RawQuery = q.Encode()
	finalURL := parsedURL.String()
	fmt.Println(finalURL)
	fmt.Printf("%+v\n", body)
	buf, err := json.Marshal(body)
	if err != nil {
		lg.Error("Failed to marshal zscaler payload to JSON", "error", err)
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, finalURL, bytes.NewBuffer(buf))
	if err != nil {
		lg.Error("Failed to create zscaler request", "error", err)
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")
	resp, err := zscaler.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		lg.Error("Zscaler API returned non-2xx:", "status", resp.Status)
		return false, fmt.Errorf("zscaler non-2xx: %s", resp.Status)
	}
	lg.Info("Zscaler API returned 2xx:", "status", resp.Status)
	return true, nil
}
