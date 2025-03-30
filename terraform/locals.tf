locals {
  tags = merge(
    {
      "env"        = "${var.environment}"
      "terraform"  = "true"
      "bu"         = "security"
      "RepoUrl"    = "${var.source_code_repo_url}"
      "service"    = "soar-api"
      "owner"      = "patrick-robertson"
      "author"     = "alex skoro"
      "costcentre" = "${var.cost_centre}"
    }
  )
  aws_region = "ap-southeast-2"
}
