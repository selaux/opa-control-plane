resource "aws_iam_role" "test_role" {
  name = "test_role"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Name = "Sample-IAM-Role"
  }
}

resource "aws_sagemaker_notebook_instance" "sample_ni_good" {
  name                   = "my-notebook-instance-good"
  role_arn               = aws_iam_role.test_role.arn
  instance_type          = "ml.t2.medium"
  direct_internet_access = "Disabled"

  tags = {
    Name    = "Sample-Sagemaker-Notebook-Instance"
    Purpose = "Policy Library Development"
  }
}

resource "aws_sagemaker_notebook_instance" "sample_ni_bad" {
  name                   = "my-notebook-instance-bad"
  role_arn               = aws_iam_role.test_role.arn
  instance_type          = "ml.t2.medium"
  direct_internet_access = "Enabled"

  tags = {
    Name    = "Sample-Sagemaker-Notebook-Instance"
    Purpose = "Policy Library Development"
  }
}
