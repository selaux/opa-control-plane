resource "aws_s3_bucket" "versioning_defined" {
  bucket = "my-tf-test-good-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket" "no_versioning" {
  bucket = "my-tf-test-good-bucket"
  acl    = "private"
}
resource "aws_s3_bucket" "versioning_by_different_resource" {
  bucket = "my-tf-test-bucket-versioning-by-different-resource"
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.no_versioning.id

  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "bad-tf-test-bucket"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "BADBUCKETPOLICY",
  "Statement": [
    {
      "Sid": "IPAllow",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::bad_tf_test_bucket/*",
      "Condition": {
         "IpAddress": {"aws:SourceIp": "8.8.8.8/32"}
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_policy" "bad_bucket_policy" {
  bucket = aws_s3_bucket.bad_bucket.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "BADBUCKETPOLICY",
  "Statement": [
    {
      "Sid": "IPAllow",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::bad_tf_test_bucket/*",
      "Condition": {
         "IpAddress": {"aws:SourceIp": "8.8.8.8/32"}
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket" "good_bucket" {
  bucket = "good-tf-test-bucket"
}

resource "aws_s3_bucket_policy" "good_bucket_policy" {
  bucket = aws_s3_bucket.good_bucket.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "GOODBUCKETPOLICY",
  "Statement": [
    {
      "Sid": "IPAllow",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::good_tf_test_bucket/*",
      "Condition": {
         "IpAddress": {"aws:SourceIp": "8.8.8.8/32"}
      }
    }
  ]
}
POLICY
}
