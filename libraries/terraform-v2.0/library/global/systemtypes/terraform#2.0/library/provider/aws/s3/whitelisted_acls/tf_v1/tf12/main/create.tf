provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "good-bucket" {
  bucket = "my-tf-test-good-bucket"
  acl      = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}


resource "aws_s3_bucket" "bad-bucket" {
  bucket = "my-tf-test-bad-bucket"
  acl      = "public-read"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
