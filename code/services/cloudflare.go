package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/cloudflare/cloudflare-go"
	"github.com/gin-gonic/gin"
)

var ListMap = map[string]string{
	"Instantscripts": "bee5bce88cbc4975a0271d86a885d21e",
	"SiSUProd":       "154b05661cf3464ca4b79bfefea61024",
	"SiSUDev":        "3c26fda19d7048538f3b5910b05023b3",
	"PricelineProd":  "234941e5cd95453898c419f13d29d88b",
	"PricelineDev":   "ac537fb43ea141839e6f711c3a2a00d7",
	"MyAPIProd":      "04d68d0344b44636ac0d076f578dd706",
	"MyAPIDev":       "d03b634bd1574e7ba1212f677f5cd3b1",
	"MAProd":         "81f74fc6c95d4f71a51025f4537f2cff",
	"MADev":          "0d3d9ff6fc0b41e98fa00da589e05564",
}

var AccountIDMap = map[string]string{
	"Instantscripts": "82358adfaf1f4439f500517a3afbb540",
	"SiSUProd":       "30413b4e6f2d68e5dbeeab176a9b4996",
	"SiSUDev":        "da0a1a407c7e0c42b30e50065429c5ce",
	"PricelineProd":  "97754e5ad1153d96f7a8a1534e51bb07",
	"PricelineDev":   "a40b07f1ddf540d519de376ad46529d9",
	"MyAPIProd":      "9999793c01c6762ce0e7e60e3594a865",
	"MyAPIDev":       "62e2be2f6c0f3f97414360098b5304bb",
	"MAProd":         "d355e15ec9421951345c4e6bf3051310",
	"MADev":          "3ac69dd7fa60aa6ddce7d748110c0ce5",
}

func NewCloudflareClient(apiToken string) (*cloudflare.API, error) {
	return cloudflare.NewWithAPIToken(apiToken)
}

// CheckIP queries AbuseIPDB for a single IP.
func CloudflareAddIP(c *gin.Context, ip string, account string, incidentID string, ssmClient *ssm.Client, kmsClient *kms.Client, lg *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(c, 30*time.Second)
	defer cancel()
	accountID, ok := AccountIDMap[account]
	if !ok {
		lg.Error("Cloudflare account not found in map", "account", account)
		return false, nil
	}
	list, ok := ListMap[account]
	if !ok {
		lg.Error("Cloudflare list not found in map", "account", account)
		return false, nil
	}
	cloudflareAPIToken, err := GetParam(c, ssmClient, kmsClient, account, lg)
	if err != nil {
		lg.Error("failed to get cloudflare api token", "error", err)
		return false, nil
	}
	api, err := NewCloudflareClient(cloudflareAPIToken)
	if err != nil {
		lg.Error("failed to create cloudflare client", "error", err)
		return false, err
	}
	lg.Info("Adding to list %s IOC %s", "list", list, "ip", ip)
	items := []cloudflare.ListItemCreateRequest{
		{
			IP:      &ip,
			Comment: fmt.Sprintf("Added via SOAR Incident %s", incidentID),
		},
	}
	_, err = api.CreateListItems(ctx, cloudflare.AccountIdentifier(accountID), cloudflare.ListCreateItemsParams{
		ID:    list,
		Items: items,
	})
	if err != nil {
		lg.Error("failed to add IP to cloudflare list", "error", err)
		return false, err
	}
	return true, nil
}
