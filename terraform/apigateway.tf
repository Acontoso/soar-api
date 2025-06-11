resource "aws_api_gateway_rest_api" "gateway_object" {
  #checkov:skip=CKV_AWS_237: "Ensure Create before destroy for API Gateway" - Old API reference, is enabled below
  name        = var.api_gateway_name
  description = "API Gateway to act as Web Layer to SOAR API"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  tags = local.tags
}

resource "aws_api_gateway_resource" "proxy_resource" {
  #When you define {proxy+}, it means that the API Gateway will match any path that comes after the base path, allowing for a flexible proxy setup.
  #If you want to access the root path, you need to ensure that the root resource is defined correctly as its own resource like this one.
  rest_api_id = aws_api_gateway_rest_api.gateway_object.id
  parent_id   = aws_api_gateway_rest_api.gateway_object.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "proxy_method_lambda" {
  #checkov:skip=CKV2_AWS_53: "Ensure AWS API gateway request is validated" -> Done at the application layer (Lambda)
  rest_api_id          = aws_api_gateway_rest_api.gateway_object.id
  resource_id          = aws_api_gateway_resource.proxy_resource.id
  http_method          = "ANY"
  api_key_required     = true
  authorization        = "COGNITO_USER_POOLS"
  authorizer_id        = aws_api_gateway_authorizer.cognito_authorizer.id
  authorization_scopes = ["soar-api/admin.readwrite.all"]
}

resource "aws_api_gateway_integration" "lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.gateway_object.id
  resource_id             = aws_api_gateway_resource.proxy_resource.id
  http_method             = aws_api_gateway_method.proxy_method_lambda.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.lambda.invoke_arn
  timeout_milliseconds    = 29000
}

resource "aws_api_gateway_deployment" "single_deployment" {
  #if you update the resource policy after the API is created, you'll need to deploy the API to propagate the changes after you've attached the updated policy
  rest_api_id = aws_api_gateway_rest_api.gateway_object.id
  triggers = {
    redeployment = sha256(data.aws_iam_policy_document.api_gateway_resource_based_policy.json)
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [aws_api_gateway_rest_api_policy.resource_based_policy_attach]
}

resource "aws_api_gateway_stage" "core_stage" {
  #checkov:skip=CKV_AWS_120: "Ensure API Gateway caching is enabled" - No caching needed for this API gateway
  #checkov:skip=CKV_AWS_73: "Ensure API Gateway has X-Ray Tracing enabled"
  #checkov:skip=CKV_AWS_76: "Ensure API Gateway has Access Logging enabled" - This is done at the application level, no need at the moment
  #checkov:skip=CKV2_AWS_29: "Ensure public API gateway are protected by WAF" - Not needed currently, will eventually be behind Cloudflare WAF. Gateway locked down via IP & authenticated requests that includes rate limiting
  #checkov:skip=CKV2_AWS_4: "Ensure API Gateway stage have logging level defined as appropriate" - Done currently at application layer
  #checkov:skip=CKV2_AWS_51: "Ensure AWS API Gateway endpoints uses client certificate authentication
  #Todo, access logs configuration
  rest_api_id   = aws_api_gateway_rest_api.gateway_object.id
  stage_name    = var.stage_name_api_gateway
  deployment_id = aws_api_gateway_deployment.single_deployment.id
  tags          = local.tags
}

resource "aws_api_gateway_usage_plan_key" "key_assign_usage_plan" {
  key_id        = aws_api_gateway_api_key.apikey_tf.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.default_usage_plan.id
}

resource "aws_api_gateway_api_key" "apikey_tf" {
  name = "core-key"
}

data "aws_iam_policy_document" "api_gateway_resource_based_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["execute-api:Invoke"]
    resources = ["${aws_api_gateway_rest_api.gateway_object.execution_arn}/*/*/*"]

    condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"
      values   = var.trusted_ip_list_api_gw
    }
  }
}

resource "aws_api_gateway_rest_api_policy" "resource_based_policy_attach" {
  rest_api_id = aws_api_gateway_rest_api.gateway_object.id
  policy      = data.aws_iam_policy_document.api_gateway_resource_based_policy.json
}

resource "aws_api_gateway_usage_plan" "default_usage_plan" {
  name        = var.api_gateway_usage_plan_name
  description = "Usage plan for API throttling and rate limiting"

  throttle_settings {
    burst_limit = var.api_burst_limit
    rate_limit  = var.api_rate_limit
  }
  api_stages {
    api_id = aws_api_gateway_rest_api.gateway_object.id
    stage  = aws_api_gateway_stage.core_stage.stage_name
  }
  tags = local.tags
}

########OpenID Connect Authorizer##########
resource "aws_api_gateway_authorizer" "cognito_authorizer" {
  name          = var.apigw_cognito_authorizer_name
  rest_api_id   = aws_api_gateway_rest_api.gateway_object.id
  type          = "COGNITO_USER_POOLS"
  provider_arns = [aws_cognito_user_pool.oidc_userpool.arn]
}
