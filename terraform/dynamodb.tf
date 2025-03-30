resource "aws_dynamodb_table" "ioc_table" {
  #checkov:skip=CKV_AWS_119: "Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK"
  name                        = var.dynamodb_table_name
  billing_mode                = "PAY_PER_REQUEST"
  deletion_protection_enabled = true
  hash_key                    = "IOC"
  range_key                   = "Source"

  attribute {
    name = "IOC"
    type = "S"
  }

  attribute {
    name = "Source"
    type = "S"
  }
  point_in_time_recovery {
    enabled = true
  }
  tags = local.tags
}

resource "aws_dynamodb_table" "actions_table" {
  #checkov:skip=CKV_AWS_119: "Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK"
  name                        = var.dynamodb_table_name_actions
  billing_mode                = "PAY_PER_REQUEST"
  deletion_protection_enabled = true
  hash_key                    = "IOC"
  range_key                   = "Integration"

  attribute {
    name = "IOC"
    type = "S"
  }

  attribute {
    name = "Integration"
    type = "S"
  }
  point_in_time_recovery {
    enabled = true
  }
  tags = local.tags
}
