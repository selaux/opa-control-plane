# AMI
data "aws_ami" "amazon_linux" {
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  owners      = ["amazon"]
  most_recent = true
}

resource "aws_launch_configuration" "launch_conf" {
  name                        = var.launch_conf_name
  image_id                    = data.aws_ami.amazon_linux.id
  instance_type               = var.instance_type
  associate_public_ip_address = true # this should trigger the warning mentioned in the README

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "asg" {
  name                 = var.asg_name
  launch_configuration = aws_launch_configuration.launch_conf.name
  min_size             = 1
  max_size             = 3
}
