resource "aws_ebs_volume" "bad_resource" {
  availability_zone = "us-west-2c"
  size              = 40

  tags = {
    Name = "bad_resource"
  }
}

resource "aws_ebs_volume" "bad_resource1" {
  availability_zone = "us-west-2c"
  size              = 40

  tags = {
    Name = "bad_resource1"
  }

  encrypted = false
}

resource "aws_ebs_volume" "good_resource" {
  availability_zone = "us-west-2c"
  size              = 40

  tags = {
    Name = "good_resource"
  }
  encrypted = true
}
