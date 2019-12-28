terraform {
  required_version = ">= 0.12.18"

  backend "s3" {
    bucket                  = var.bucket
    key                     = "iam.tfstate"
    region                  = "ap-northeast-1"
    shared_credentials_file = "~/.aws/credentials"
    profile                 = var.aws_profile
  }
}
