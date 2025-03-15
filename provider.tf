terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
    backend "s3" {
        bucket = "demo-running-tfstate"
        key = "terraform.tfstate"
        region = "ap-northeast-2"
    }
}

# Configure the AWS Provider
provider "aws" {
  region = "ap-northeast-2"
  access_key = {{ secret.AWS_ACCESS_KEY_ID }} 
  secret_key = {{ secret.AWS_SECRET_ACCESS_KEY }}
}