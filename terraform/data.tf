data "aws_kms_key" "ssm_kms_alias" {
  key_id = "alias/cmk-ssm"
}

data "aws_s3_bucket" "artefact_bucket" {
  bucket = "security-terraform-state-weshealth"
}

data "aws_s3_object" "lambda_zip" {
  bucket = data.aws_s3_bucket.artefact_bucket.id
  key    = "application.zip"
  depends_on = [null_resource.upload_lambda_zip]
}
