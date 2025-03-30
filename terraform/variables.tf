variable "source_code_repo_url" {
  type        = string
  description = "Repository where IaC and Lambda function source code resides"
}

variable "environment" {
  description = "Environment the infrastructure is deployed in"
  type        = string
}

variable "cost_centre" {
  description = "Cost centre to apply the resources too"
  type        = string
}

variable "dynamodb_table_name" {
  description = "Name of the DyanamoDB table that will store data"
  type        = string
}

variable "dynamodb_table_name_actions" {
  description = "Name of the DyanamoDB table that will store SOAR actions"
  type        = string
}

variable "api_gateway_name" {
  description = "Name of API Gateway"
  type        = string
}

variable "trusted_ip_list_api_gw" {
  description = "List of IP addresses that can trigger gateway"
  type        = list(string)
}

variable "api_burst_limit" {
  description = "Maximum of requests allowed within a few milliseconds, allows temp spike in traffic over the rate limit"
  type        = number
}

variable "api_rate_limit" {
  description = "Maxmium number of requests per second the API can handle"
  type        = number
}

variable "api_gateway_usage_plan_name" {
  description = "Maxmium number of requests per second the API can handle"
  type        = string
}

variable "stage_name_api_gateway" {
  description = "Name of core AWS API gateway stage that is linked to deployment & usage plan"
  type        = string
}

variable "lambda_function_name" {
  type        = string
  description = "Name of lambda function"
}

variable "sns_topic_name" {
  type        = string
  description = "SNS topic name"
}

variable "dynamodb_table" {
  type        = string
  description = "DynamoDB table used by the Lambda"
}

variable "dynamodb_primary_key" {
  type        = string
  description = "DynamoDB partition key"
}

variable "dynamodb_sort_key" {
  type        = string
  description = "DynamoDB sort key"
}

variable "dynamodb_primary_key_actions" {
  type        = string
  description = "DynamoDB partition key"
}

variable "dynamodb_sort_key_actions" {
  type        = string
  description = "DynamoDB sort key"
}

variable "runtime" {
  type        = string
  description = "Lambda runtime language and version"
}

variable "handler" {
  type        = string
  description = "Specify file & main entry point of Lambda function"
}

variable "memory_size" {
  type        = string
  description = "Size of memory to allocate Lambda function during runtime"
}

variable "timeout" {
  type        = number
  description = "Lambda function timeout"
}

variable "description" {
  type        = string
  description = "What does this stupid function do"
}

variable "enc_string_anomali_user" {
  type        = string
  description = "Anomali username for API integration"
}

variable "enc_string_anomali_api" {
  type        = string
  description = "Anomali API key for integration"
}

variable "enc_string_ipabuse_db" {
  type        = string
  description = "IPAbuse DB API Key"
}

variable "enc_string_datp_client_id" {
  type        = string
  description = "Azure DATP encrypted client id"
}

variable "enc_string_datp_client_secret" {
  type        = string
  description = "Azure DATP encrypted client secret"
}

variable "enc_string_urlscan_client_secret" {
  type        = string
  description = "URLScan API Key"
}

variable "enc_string_graph_client_id" {
  type        = string
  description = "Graph API client id"
}

variable "enc_string_graph_client_secret" {
  type        = string
  description = "Graph API client secret"
}

variable "ms_tenant_id" {
  type        = string
  description = "Microsoft Tenant ID specific to this installation"
}

variable "congnito_oidc_userpool" {
  type        = string
  description = "Name of cognito userpool used to run OIDC service for client credential flow"
}

variable "congnito_oidc_client_app" {
  type        = string
  description = "Client app that represents the consumer service authenticating to soar API"
}

variable "cognito_domain_name" {
  type        = string
  description = "Cognito domain name (sub domain) to create when building out Oauth service"
}

variable "apigw_cognito_authorizer_name" {
  type        = string
  description = "Used to verify the token is legitimate when reaching API gateway"
}
