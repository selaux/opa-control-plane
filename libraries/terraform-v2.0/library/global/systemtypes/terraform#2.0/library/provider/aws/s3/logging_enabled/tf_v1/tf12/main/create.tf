provider "aws" {
  profile = "default"
  region  = "us-east-1"
}

resource "aws_s3_bucket" "good" {
  bucket = "my-tf-test-bucket_good"
  acl    = "private"

  logging {
    target_bucket = "bundle-registry-01"
    target_prefix = "log/"
  }
}

resource "aws_s3_bucket" "bad" {
  bucket = "my-tf-test-bucket_bad"
  acl    = "private"
}
