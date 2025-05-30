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

resource "aws_ecs_service" "mongo" {
  name = "mongodb"
  #cluster         = aws_ecs_cluster.foo.id
  #task_definition = aws_ecs_task_definition.mongo.arn
  #desired_count   = 3
  iam_role = aws_iam_role.test_role.arn

  ordered_placement_strategy {
    type  = "binpack"
    field = "cpu"
  }

  network_configuration { # Optional block, but users needs to have this block if they want to check assign_public_ip
    subnets          = [aws_subnet.subnet.id]
    assign_public_ip = false # Optinal argurment
  }

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:ecs.availability-zone in [us-west-2a, us-west-2b]"
  }
}