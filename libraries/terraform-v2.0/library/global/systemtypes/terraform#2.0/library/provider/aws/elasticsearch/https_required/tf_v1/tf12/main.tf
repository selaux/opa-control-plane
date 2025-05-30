terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }
}

provider "aws" {
  profile = "default"
  region  = "us-west-2"
}  

resource "aws_elasticsearch_domain" "elasticsearch_domain" {
  domain_name           = "domain1"
  elasticsearch_version = "7.10"
  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
  cluster_config {
    instance_type = "r4.large.elasticsearch"
  }
  tags = {
    Domain = "TestDomain"
  }
}
