data "aws_iam_policy" "AWSElasticBeanstalkService" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService"
}

resource "aws_iam_role_policy_attachment" "eb_service_role" {
  role       = aws_iam_role.eb_service_role.name
  policy_arn = data.aws_iam_policy.AWSElasticBeanstalkService.arn
}

data "aws_iam_policy" "AWSElasticBeanstalkEnhancedHealth" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth"
}

resource "aws_iam_role_policy_attachment" "eb_service_role_2" {
  role       = aws_iam_role.eb_service_role.name
  policy_arn = data.aws_iam_policy.AWSElasticBeanstalkEnhancedHealth.arn
}

resource "aws_iam_role" "eb_service_role" {
  name = "beanstalk-service-role"
  tags = {
    Environment = terraform.workspace
  }
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "elasticbeanstalk.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
