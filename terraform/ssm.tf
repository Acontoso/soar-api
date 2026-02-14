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

resource "aws_ssm_parameter" "zscaler_client_id" {
  name        = "/soar-api/zscaler_client_id"
  type        = "SecureString"
  description = "Anomali API key for integration"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_zscaler_client_id
  tags        = local.tags
}

resource "aws_ssm_parameter" "zscaler_client_secret" {
  name        = "/soar-api/zscaler_client_secret"
  type        = "SecureString"
  description = "IPAbuse DB API Key"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_zscaler_client_secret
  tags        = local.tags
}

########################Cloudflare API Tokens ########################
resource "aws_ssm_parameter" "cf_is_token" {
  name        = "/soar-api/Instantscripts"
  type        = "SecureString"
  description = "Cloudflare IS API Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_is_token
  tags        = local.tags
}

resource "aws_ssm_parameter" "cf_myapidev_token" {
  name        = "/soar-api/MyAPIDev"
  type        = "SecureString"
  description = "Cloudflare MyAPI Dev Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_myapidev_token
  tags        = local.tags
}

resource "aws_ssm_parameter" "cf_myapiprod_token" {
  name        = "/soar-api/MyAPIProd"
  type        = "SecureString"
  description = "Cloudflare MyAPI Prod Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_myapiprod_token
  tags        = local.tags
}

resource "aws_ssm_parameter" "cf_madev_token" {
  name        = "/soar-api/MADev"
  type        = "SecureString"
  description = "Cloudflare MA Dev Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_madev_token
  tags        = local.tags
}

resource "aws_ssm_parameter" "cf_maprod_token" {
  name        = "/soar-api/MAProd"
  type        = "SecureString"
  description = "Cloudflare MA Prod Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_maprod_token
  tags        = local.tags
}

resource "aws_ssm_parameter" "cf_pricelinedev_token" {
  name        = "/soar-api/PricelineDev"
  type        = "SecureString"
  description = "Cloudflare Priceline Dev Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_pricelinedev_token
  tags        = local.tags
}

resource "aws_ssm_parameter" "cf_pricelineprod_token" {
  name        = "/soar-api/PricelineProd"
  type        = "SecureString"
  description = "Cloudflare Priceline Prod Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_pricelineprod_token
  tags        = local.tags
}

resource "aws_ssm_parameter" "cf_sisudev_token" {
  name        = "/soar-api/SiSUDev"
  type        = "SecureString"
  description = "Cloudflare SISU Dev Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_sisudev_token
  tags        = local.tags
}

resource "aws_ssm_parameter" "cf_sisuprod_token" {
  name        = "/soar-api/SiSUProd"
  type        = "SecureString"
  description = "Cloudflare SISU Prod Token"
  key_id      = data.aws_kms_key.ssm_kms_alias.id
  value       = var.enc_cf_api_sisuprod_token
  tags        = local.tags
}
