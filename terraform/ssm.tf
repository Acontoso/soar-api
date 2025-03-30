#aws kms encrypt --key-id <key id> --plaintext fileb://<(echo -n 'secret') --output text --query CiphertextBlob
resource "aws_ssm_parameter" "anomali_user" {
  name        = "/soar-api/anomali_user"
  type        = "SecureString"
  description = "Anomali username for API integration"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_string_anomali_user
  tags        = local.tags
}

resource "aws_ssm_parameter" "anomali_api" {
  name        = "/soar-api/anomali_api"
  type        = "SecureString"
  description = "Anomali API key for integration"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_string_anomali_api
  tags        = local.tags
}

resource "aws_ssm_parameter" "ipabuse_db" {
  name        = "/soar-api/ipabuse_db"
  type        = "SecureString"
  description = "IPAbuse DB API Key"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_string_ipabuse_db
  tags        = local.tags
}

resource "aws_ssm_parameter" "datp_client_id" {
  name        = "/soar-api/datp_client_id"
  type        = "SecureString"
  description = "Azure DATP encrypted client id"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_string_datp_client_id
  tags        = local.tags
}

resource "aws_ssm_parameter" "datp_client_secret" {
  name        = "/soar-api/datp_client_secret"
  type        = "SecureString"
  description = "Azure DATP encrypted client secret"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_string_datp_client_secret
  tags        = local.tags
}

resource "aws_ssm_parameter" "urlscan" {
  name        = "/soar-api/urlscan"
  type        = "SecureString"
  description = "Azure DATP encrypted client secret"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_string_urlscan_client_secret
  tags        = local.tags
}

resource "aws_ssm_parameter" "graph_client_id" {
  name        = "/soar-api/graph_client_id"
  type        = "SecureString"
  description = "Graph API encrypted client id"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_string_graph_client_id
  tags        = local.tags
}

resource "aws_ssm_parameter" "graph_client_secret" {
  name        = "/soar-api/graph_client_secret"
  type        = "SecureString"
  description = "Graph API encrypted client secret"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_string_graph_client_secret
  tags        = local.tags
}
