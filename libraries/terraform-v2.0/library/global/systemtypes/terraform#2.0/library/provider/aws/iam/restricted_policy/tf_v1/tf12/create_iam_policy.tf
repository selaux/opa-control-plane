resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
     {
      "Sid": "Stmt1616762744855",
      "Action": [
        "s3:BypassGovernanceRetention",
        "s3:CreateBucket",
        "s3:CreateJob",
        "s3:DeleteAccessPoint"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::styra-onprem-test01"
    },
    ]
  })
}
