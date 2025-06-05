resource "null_resource" "upload_lambda_zip" {
  triggers = {
    always_run = timestamp()
  }
  depends_on = [data.archive_file.code]
  provisioner "local-exec" {
    command = "aws s3 cp ${path.root}/terraform/application.zip s3://${data.aws_s3_bucket.artefact_bucket.id}/application.zip"
  }
}

resource "aws_lambda_function" "lambda" {
  #checkov:skip=CKV_AWS_117: "Ensure that AWS Lambda function is configured inside a VPC"
  #checkov:skip=CKV_AWS_272: "Ensure AWS Lambda function is configured to validate code-signing"
  #checkov:skip=CKV_AWS_116: "Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ)"
  #checkov:skip=CKV_AWS_50: "X-ray tracing is enabled for Lambda"
  #checkov:skip=CKV_AWS_115: "Ensure that AWS Lambda function is configured for function-level concurrent execution limit"
  #checkov:skip=CKV_AWS_173: "Check encryption settings for Lambda environmental variable"
  function_name    = var.lambda_function_name
  role             = aws_iam_role.lambda_role.arn
  s3_bucket         = data.aws_s3_bucket.artefact_bucket.id
  s3_key            = "application.zip"
  handler           = var.handler
  runtime           = var.runtime
  memory_size       = var.memory_size
  tags              = local.tags
  timeout           = var.timeout
  description       = var.description
  source_code_hash  = data.aws_s3_object.lambda_zip.etag
  logging_config {
    log_format = "JSON"
  }
  environment {
    variables = {
      "TABLE"                = var.dynamodb_table
      "PARTITION_KEY"        = var.dynamodb_primary_key
      "SORT_KEY"             = var.dynamodb_sort_key
      "ACTION_TABLE"         = var.dynamodb_table_name_actions
      "ACTION_PARTITION_KEY" = var.dynamodb_primary_key_actions
      "ACTION_SORT_KEY"      = var.dynamodb_sort_key_actions
      "TENANT_ID"            = var.ms_tenant_id
    }
  }
  depends_on = [null_resource.upload_lambda_zip]
}

resource "null_resource" "pip_install" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    command = "python3 -m pip install -r ${path.module}/../requirements.txt -t ${path.module}/../ && python3 -m pip install --platform manylinux2014_x86_64 --implementation cp --python-version 3.11 --only-binary=:all: --upgrade cryptography -t ${path.module}/../"
  }
}

data "archive_file" "code" {
  type        = "zip"
  source_dir  = "${path.module}/.." # Use parent dir so application/ is at root
  output_path = "${path.root}/terraform/application.zip" # Use absolute path for CI/CD reliability
  excludes    = ["env/*", "terraform/*","workloads/*", "README.md" ,"tests/*", "*.pyc", "__pycache__/*", "openapi.yaml", ".git/*", ".gitignore"]
  depends_on  = [null_resource.pip_install]
}

data "aws_iam_policy_document" "lambda_custom_execution_policy" {
  version = "2012-10-17"
  statement {
    sid    = "AllowSSM"
    effect = "Allow"
    actions = [
      "ssm:GetParameter*"
    ]
    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/soar-api/*"
    ]
  }
  statement {
    sid    = "AllowSnsPublish"
    effect = "Allow"
    actions = [
      "sns:Publish",
    ]
    resources = [
      module.sns.sns_topic_arn
    ]
  }
  statement {
    sid    = "AllowKMS"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      data.aws_kms_key.ssm_kms_alias.arn
    ]
  }
  statement {
    sid    = "AllowDynamoDB"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
      "dynamodb:GetItem"
    ]
    resources = [
      aws_dynamodb_table.ioc_table.arn,
      aws_dynamodb_table.actions_table.arn
    ]
  }
}

resource "aws_iam_policy" "lambda_iam_policy" {
  name   = "${var.lambda_function_name}-lambda-policy"
  policy = data.aws_iam_policy_document.lambda_custom_execution_policy.json
  tags   = local.tags
}

resource "aws_iam_role" "lambda_role" {
  name               = "${var.lambda_function_name}-lambda-execution-role"
  assume_role_policy = data.aws_iam_policy_document.trust_policy_document_lambda.json
  tags               = local.tags
}

data "aws_iam_policy_document" "trust_policy_document_lambda" {
  statement {
    sid    = "LambdaTrustPolicy"
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      identifiers = [
        "lambda.amazonaws.com",
      ]

      type = "Service"
    }
  }
}

resource "aws_iam_policy_attachment" "policy_attachment_lambda_role" {
  name       = "role-policy-attachment"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = aws_iam_policy.lambda_iam_policy.arn
}

resource "aws_iam_role_policy_attachment" "default_policy_attachment_lambda_role" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function_event_invoke_config" "lambda_retry_failure" {
  function_name                = aws_lambda_function.lambda.function_name
  maximum_event_age_in_seconds = 21600
  maximum_retry_attempts       = 0
  destination_config {
    on_failure {
      destination = module.sns.sns_topic_arn
    }
  }
}

resource "aws_lambda_permission" "api_gateway_trigger" {
  statement_id  = "AllowExecutionFromAPIGW"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.gateway_object.execution_arn}/*/*/*" #All methods and stages
}

resource "null_resource" "check_zip" {
  depends_on = [data.archive_file.code]
  provisioner "local-exec" {
    command = "ls -lh ${path.root}/terraform/application.zip && unzip -l ${path.root}/terraform/application.zip"
  }
}
