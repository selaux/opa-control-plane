provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "examplebucket" {
  bucket = "examplebuckettftest"
  acl    = "private"
}

resource "aws_s3_bucket_object" "examplebucket_object" {
  key                    = "someobject1"
  bucket                 = aws_s3_bucket.examplebucket.id
  source                 = "index.html"
  server_side_encryption = "aws:kms"
}

resource "aws_s3_object" "examplebucket_object" {
  key                    = "someobject2"
  bucket                 = aws_s3_bucket.examplebucket.id
  source                 = "index.html"
  server_side_encryption = "aws:kms"
}
