package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Acontoso/soar-api/code/models"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/gin-gonic/gin"
)

// var IOC_TABLE_NAME string = os.Getenv("IOC_TABLE_NAME")
var IOC_TABLE_NAME string = "ioc-finder"
var IOC_TABLE_HASH_KEY string = "IOC"
var IOC_TABLE_SORT_KEY string = "EnrichmentSource"

var SOAR_ACTIONS_TABLE_NAME string = "soar-actions"
var SOAR_ACTIONS_TABLE_HASH_KEY string = "IOC"
var SOAR_ACTIONS_SORT_KEY string = "Integration"

var (
	ErrNotFound   = errors.New("Item not found")
	ErrNoDBClient = errors.New("Dynamodb client missing")
)

// NewDynamoDBClient initializes and returns a DynamoDB client

func NewDynamoDBClient(ctx context.Context) (*dynamodb.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-southeast-2"))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return dynamodb.NewFromConfig(cfg), nil
}

func getKeyIOC(ioc models.IOCTable) map[string]types.AttributeValue {
	IOC, err := attributevalue.Marshal(ioc.IOC)
	if err != nil {
		panic(err)
	}
	Source, err := attributevalue.Marshal(ioc.EnrichmentSource)
	if err != nil {
		panic(err)
	}
	return map[string]types.AttributeValue{"IOC": IOC, "EnrichmentSource": Source}
}

func GetItemIOCFinder(c *gin.Context, client *dynamodb.Client, hash_key_value string, sort_key_value string, lg *slog.Logger) (*models.IOCTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.IOCTable{
		IOC:              hash_key_value,
		EnrichmentSource: sort_key_value,
	}

	resp, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &IOC_TABLE_NAME,
		Key:       getKeyIOC(*data),
	})
	if err != nil {
		lg.Error("Error pulling data from database", "error", err)
		return nil, nil
	}

	if resp.Item == nil || len(resp.Item) == 0 {
		return nil, ErrNotFound
	}

	if err := attributevalue.UnmarshalMap(resp.Item, data); err != nil {
		lg.Error("Couldn't unmarshal response", "error", err)
		return nil, err
	}

	return data, nil
}

func PutItemIOCFinder(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data *models.IOCTable) error {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	item, err := attributevalue.MarshalMap(data)
	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &IOC_TABLE_NAME,
		Item:      item,
	})
	if err != nil {
		lg.Error("Couldn't add item to table. Here's why: %v\n", err)
	}
	return err
}

func getKeySOAR(ioc models.SOARTable) map[string]types.AttributeValue {
	IOC, err := attributevalue.Marshal(ioc.IOC)
	if err != nil {
		panic(err)
	}
	Integration, err := attributevalue.Marshal(ioc.Integration)
	if err != nil {
		panic(err)
	}
	return map[string]types.AttributeValue{"IOC": IOC, "Integration": Integration}
}

func GetItemSOAR(c *gin.Context, client *dynamodb.Client, hash_key_value string, sort_key_value string, lg *slog.Logger) (*models.SOARTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.SOARTable{
		IOC:         hash_key_value,
		Integration: sort_key_value,
	}

	resp, err := client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &SOAR_ACTIONS_TABLE_NAME,
		Key:       getKeySOAR(*data),
	})
	if err != nil {
		lg.Error("Error pulling data from database", "error", err)
		return nil, nil
	}

	if resp.Item == nil || len(resp.Item) == 0 {
		return nil, ErrNotFound
	}

	if err := attributevalue.UnmarshalMap(resp.Item, data); err != nil {
		lg.Error("Couldn't unmarshal response", "error", err)
		return nil, err
	}

	return data, nil
}

func PutItemSOAR(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data *models.SOARTable) error {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	item, err := attributevalue.MarshalMap(data)
	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &SOAR_ACTIONS_TABLE_NAME,
		Item:      item,
	})
	if err != nil {
		lg.Error("Couldn't add item to table. Here's why: %v\n", err)
	}
	return err
}
