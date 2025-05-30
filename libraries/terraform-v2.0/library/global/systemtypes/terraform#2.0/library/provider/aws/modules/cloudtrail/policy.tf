resource "aws_s3_bucket_policy" "CloudTrailS3Bucket" {
    bucket = aws_s3_bucket.bucket1.id
    depends_on = [aws_s3_bucket.bucket1]
    policy = <<POLICY
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:GetBucketAcl",
                "Resource": "${aws_s3_bucket.bucket1.arn}"
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": "${aws_s3_bucket.bucket1.arn}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            }
        ]
}   
POLICY
}
