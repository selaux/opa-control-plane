data "aws_caller_identity" "current" {}

data "aws_kms_key" "by_alias_arn" {
    key_id = "arn:aws:kms:${var.region}:${data.aws_caller_identity.current.account_id}:alias/cloudtrail"
}

resource "aws_cloudtrail" "cloudtrail_sample" {
    name                          = "tf-trail-sample"
    s3_bucket_name                = aws_s3_bucket.bucket1.id
    s3_key_prefix                 = "prefix"
    include_global_service_events = false
    kms_key_id = data.aws_kms_key.by_alias_arn.key_id
    depends_on = [aws_s3_bucket_policy.CloudTrailS3Bucket, aws_s3_bucket.bucket1]
}

resource "aws_s3_bucket" "bucket1" {
    bucket        = "some-bucket-for-cloud-trail-tf-policy-library"
    force_destroy = true
}
