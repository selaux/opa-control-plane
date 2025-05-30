provider "aws" {
  profile = "default"
  region  = "us-east-1"
}

########################################
# aws_iam_policy
########################################
resource "aws_iam_policy" "good_iam_policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "bad_iam_policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:CreateAccessKey",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

########################################
# aws_iam_role_policy
########################################

resource "aws_iam_role_policy" "good_role_policy" {
  name = "good_role_policy"
  role = aws_iam_role.good_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "bad_role_policy" {
  name = "bad_role_policy"
  role = aws_iam_role.good_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:ListAccessKeys",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role" "good_role" {
  name = "good_role"

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
}

########################################
# aws_iam_user_policy
########################################

resource "aws_iam_user_policy" "good_user_policy" {
  name = "test"
  user = aws_iam_user.good_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_user_policy" "bad_user_policy" {
  name = "test"
  user = aws_iam_user.good_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "iam:*"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_user" "good_user" {
  name = "loadbalancer"
  path = "/system/"
}

resource "aws_iam_access_key" "good_user" {
  user = aws_iam_user.good_user.name
}

########################################
# aws_iam_group_policy
########################################

resource "aws_iam_group_policy" "good_group_policy" {
  name  = "good_group_policy"
  group = aws_iam_group.good_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_group_policy" "bad_group_policy" {
  name  = "bad_group_policy"
  group = aws_iam_group.good_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:UpdateAccessKey",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_group" "good_group" {
  name = "developers"
  path = "/users/"
}
