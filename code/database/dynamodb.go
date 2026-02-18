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

func getKeysIOC(ioc models.IOCTableBatch) []map[string]types.AttributeValue {
	keys := make([]map[string]types.AttributeValue, len(ioc.IOC))
	EnrichmentSource, err := attributevalue.Marshal(ioc.EnrichmentSource)
	if err != nil {
		panic(err)
	}
	for i, ioc := range ioc.IOC {
		keys[i] = map[string]types.AttributeValue{
			"IOC":              &types.AttributeValueMemberS{Value: ioc},
			"EnrichmentSource": EnrichmentSource,
		}
	}
	return keys
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

func GetItemsIOCFinder(c *gin.Context, client *dynamodb.Client, hash_key_values []string, sort_key_value string, lg *slog.Logger) ([]models.IOCTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.IOCTableBatch{
		IOC:              hash_key_values,
		EnrichmentSource: sort_key_value,
	}

	resp, err := client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			IOC_TABLE_NAME: {
				Keys: getKeysIOC(*data),
			},
		},
	})
	if err != nil {
		lg.Error("Error pulling data from database", "error", err)
		return nil, nil
	}

	if resp.Responses == nil || len(resp.Responses) == 0 {
		return nil, ErrNotFound
	}

	var results []models.IOCTable
	for _, item := range resp.Responses[IOC_TABLE_NAME] {
		var record models.IOCTable
		if err := attributevalue.UnmarshalMap(item, &record); err != nil {
			lg.Error("Couldn't unmarshal response", "error", err)
			continue
		}
		results = append(results, record)
	}

	return results, nil
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

func PutItemsIOCFinder(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data []models.IOCTable) error {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	const batchSize = 25

	for i := 0; i < len(data); i += batchSize {
		end := i + batchSize
		if end > len(data) {
			end = len(data)
		}
		batch := data[i:end]

		writeRequests := make([]types.WriteRequest, len(batch))
		for j, item := range batch {
			marshaledItem, err := attributevalue.MarshalMap(item)
			if err != nil {
				lg.Error("Failed to marshal item", "error", err)
				continue
			}
			writeRequests[j] = types.WriteRequest{
				PutRequest: &types.PutRequest{
					Item: marshaledItem,
				},
			}
		}

		_, err := client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]types.WriteRequest{
				IOC_TABLE_NAME: writeRequests,
			},
		})
		if err != nil {
			lg.Error("Couldn't batch write items", "error", err)
			return err
		}
	}

	return nil
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

func getKeysSOAR(ioc models.SOARTableBatch) []map[string]types.AttributeValue {
	keys := make([]map[string]types.AttributeValue, len(ioc.IOC))
	Integration, err := attributevalue.Marshal(ioc.Integration)
	if err != nil {
		panic(err)
	}
	for i, ioc := range ioc.IOC {
		keys[i] = map[string]types.AttributeValue{
			"IOC":         &types.AttributeValueMemberS{Value: ioc},
			"Integration": Integration,
		}
	}
	return keys
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

func GetItemsSOAR(c *gin.Context, client *dynamodb.Client, hash_key_values []string, sort_key_value string, lg *slog.Logger) ([]models.SOARTable, error) {
	// use request context so timeouts/cancellation propagate
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return nil, ErrNoDBClient
	}
	//pointer since it will let you return nil if item not present
	data := &models.SOARTableBatch{
		IOC:         hash_key_values,
		Integration: sort_key_value,
	}

	resp, err := client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			SOAR_ACTIONS_TABLE_NAME: {
				Keys: getKeysSOAR(*data),
			},
		},
	})
	if err != nil {
		lg.Error("Error pulling data from database", "error", err)
		return nil, nil
	}

	if resp.Responses == nil || len(resp.Responses) == 0 {
		return nil, ErrNotFound
	}

	var results []models.SOARTable
	for _, item := range resp.Responses[SOAR_ACTIONS_TABLE_NAME] {
		var record models.SOARTable
		if err := attributevalue.UnmarshalMap(item, &record); err != nil {
			lg.Error("Couldn't unmarshal response", "error", err)
			continue
		}
		results = append(results, record)
	}

	return results, nil
}

func PutItemsSOAR(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, data []models.SOARTable) error {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	const batchSize = 25

	for i := 0; i < len(data); i += batchSize {
		end := i + batchSize
		if end > len(data) {
			end = len(data)
		}
		batch := data[i:end]

		writeRequests := make([]types.WriteRequest, len(batch))
		for j, item := range batch {
			marshaledItem, err := attributevalue.MarshalMap(item)
			if err != nil {
				lg.Error("Failed to marshal item", "error", err)
				continue
			}
			writeRequests[j] = types.WriteRequest{
				PutRequest: &types.PutRequest{
					Item: marshaledItem,
				},
			}
		}

		_, err := client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]types.WriteRequest{
				SOAR_ACTIONS_TABLE_NAME: writeRequests,
			},
		})
		if err != nil {
			lg.Error("Couldn't batch write items", "error", err)
			return err
		}
	}

	return nil
}

func UpdateItemSOARAccounts(c *gin.Context, client *dynamodb.Client, lg *slog.Logger, ioc string, integration string, account string) error {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	if client == nil {
		lg.Error("dynamodb client is nil")
		return ErrNoDBClient
	}

	key := map[string]types.AttributeValue{
		"IOC":         &types.AttributeValueMemberS{Value: ioc},
		"Integration": &types.AttributeValueMemberS{Value: integration},
	}

	updateExpression := "SET Info.Accounts = list_append(if_not_exists(Info.Accounts, :empty_list), :new_account)"

	_, err := client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        &SOAR_ACTIONS_TABLE_NAME,
		Key:              key,
		UpdateExpression: &updateExpression,
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":new_account": &types.AttributeValueMemberL{
				Value: []types.AttributeValue{
					&types.AttributeValueMemberS{Value: account},
				},
			},
			":empty_list": &types.AttributeValueMemberL{Value: []types.AttributeValue{}},
		},
	})

	if err != nil {
		lg.Error("Couldn't update item", "error", err)
		return err
	}

	return nil
}
