data "aws_kms_key" "ssm_kms_alias" {
  key_id = "alias/cmk-ssm"
}
