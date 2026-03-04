data "aws_iam_policy_document" "assume_role_gateway" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gateway_role" {
  name               = "bedrock-agentcore-gateway-role-soar-api"
  assume_role_policy = data.aws_iam_policy_document.assume_role_gateway.json
}

resource "aws_iam_role_policy_attachment" "default_policy_attachment_lambda_role_gateway" {
  role       = aws_iam_role.gateway_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "bedrock_agent_custom_execution_policy" {
  version = "2012-10-17"
  statement {
    sid    = "AllowBedrockAgentCoreAccessToken"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:GetWorkloadAccessToken",
      "bedrock-agentcore:GetResourceOauth2Token",
    ]
    resources = [
      "arn:aws:bedrock-agentcore:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workload-identity-directory/default",
      "arn:aws:bedrock-agentcore:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workload-identity-directory/default/workload-identity/${var.gateway_name}-*"
    ]
  }
  statement {
    sid    = "AllowBedrockAgentCoreAuth2"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:GetResourceOauth2Token",
    ]
    resources = [
      "arn:aws:bedrock-agentcore:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:token-vault/default*",
    ]
  }
  statement {
    sid    = "GetSecretValue"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:*",
    ]
  }
}

resource "aws_iam_policy" "bedrock_agent_custom_execution_policy" {
  name   = "agentcore-soarapi-agentcore-policy"
  policy = data.aws_iam_policy_document.bedrock_agent_custom_execution_policy.json
  tags   = local.tags
}

resource "aws_iam_policy_attachment" "policy_attachment_agentcore" {
  name       = "role-policy-attachment"
  roles      = [aws_iam_role.gateway_role.name]
  policy_arn = aws_iam_policy.bedrock_agent_custom_execution_policy.arn
}
