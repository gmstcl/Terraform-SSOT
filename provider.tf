terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
      bucket = "demo-running-tfstate"
      key    = "terraform.tfstate"
      region = "ap-northeast-2"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "ap-northeast-2"
}

data "terraform_remote_state" "demo" {
  backend = "s3"
  config = {
    bucket = "demo-running-tfstate"
    key    = "terraform.tfstate"
    region = "ap-northeast-2"
  }
}