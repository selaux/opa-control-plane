terraform {

  required_version = ">=1.2"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "aws" {
  alias  = "east"
  region = "us-east-1"
}
