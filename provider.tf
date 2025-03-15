terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "ap-northeast-2"
  access_key = "AKIATCKARK6C24YT4QKX" 
  secret_key = "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"
}
