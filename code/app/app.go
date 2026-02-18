package app

import (
	"github.com/Acontoso/soar-api/code/services"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/gin-gonic/gin"
)

// Creates a single app container (structure) that holds shared resources
// Lets handlers access clients from container directly instread of passing into requests contexts
// Single initialisation in main.go then passed to routes setup
type App struct {
	Router         *gin.Engine
	Dynamo         *dynamodb.Client
	KMS            *kms.Client
	SSM            *ssm.Client
	Cognito        *cognitoidentity.Client
	AbuseIPDB      *services.AbuseIPDBClient
	Anomali        *services.AnomaliClient
	Zscaler        *services.ZscalerClient
	RecordedFuture *services.FutureClient
}
