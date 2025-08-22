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
