resource "aws_instance" "instance_volume_deletion" {
  ami           = "ami-12345"
  instance_type = "t3.micro"

  ebs_block_device {
    device_name           = "/dev/sdg"
    volume_size           = 5
    volume_type           = "gp2"
    delete_on_termination = false
  }
  root_block_device {
    volume_size           = 5
    volume_type           = "gp2"
    delete_on_termination = false
    encrypted             = true
  }
  tags = {
    Name = "HelloWorld"
  }
}

resource "aws_instance" "unapproved_region" {
  provider = aws.east

  ami           = "ami-0747bdcabd34c712a"
  instance_type = "t2.micro"

  tags = {
    Name = "unapproved_region"
  }
}

resource "aws_instance" "unapproved_subnet" {
  ami           = "ami-0747bdcabd34c712a"
  instance_type = "t2.micro"
  subnet_id     = "bad_subnet_id"

  tags = {
    Name = "unapproved_subnet"
  }
}

resource "aws_instance" "unapproved_security_group" {
  ami                    = "ami-0ab4d1e9cf9a1215a"
  instance_type          = "t2.micro"
  subnet_id              = "subnet-023771e90ae07903c"

  vpc_security_group_ids = [ "sg-04980aba68695db67", "sg-084bd4138cd8e0087"]

  tags = {
    Name = "HelloWorld"
  }
}

resource "aws_instance" "metadata_options" {
  ami           = "ami-830c94e3"
  instance_type = "t2.micro"

  tags = {
    Name = "good_resource_1"
  }
  metadata_options {
    http_tokens = "required"
    http_endpoint = "enabled"
  }
}

resource "aws_launch_template" "metadata_options" {
  name = "good_resource_1"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
  }
}
resource "aws_instance" "public_ip_association_explicitly_declared" {
  ami           = "ami-830c94e3"
  instance_type = "t2.micro"
  subnet_id = "subnet-abd8438a"
  associate_public_ip_address = false  

  tags = {
    Name = "ExampleInstance"
  }
}

resource "aws_instance" "public_ip_association_undeclared" {
  ami           = "ami-830c94e3"
  instance_type = "t2.micro"
  subnet_id = "subnet-abd8438a"

  tags = {
    Name = "ExampleInstance"
  }
}

resource "aws_launch_template" "public_ip_association_explicitly_declared" {
  name = "good-example"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size = 20
    }
  }

  network_interfaces {
    associate_public_ip_address = false

  }
  placement {
    availability_zone = "us-west-2a"
  }

  ram_disk_id = "test"

  vpc_security_group_ids = ["sg-12345678"]

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "good-example"
    }
  }
}

resource "aws_launch_template" "empty_network_interfaces" {
  name = "bad-example"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size = 20
    }
  }

  network_interfaces {

  }
  placement {
    availability_zone = "us-west-2a"
  }

  ram_disk_id = "test"

  vpc_security_group_ids = ["sg-12345678"]

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "good-example"
    }
  }
}

resource "aws_launch_template" "network_interfaces_undeclared" {
  name = "bad-example-2"

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size = 20
    }
  }

  placement {
    availability_zone = "us-west-2a"
  }

  ram_disk_id = "test"

  vpc_security_group_ids = ["sg-12345678"]

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "bad-example-2"
    }
  }
}

# AMI
data "aws_ami" "amazon_linux" {
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  owners      = ["amazon"]
  most_recent = true
}

resource "aws_launch_configuration" "public_ip_association_explicitly_declared" {
  name                        = "tf-launchconf-styra"
  image_id                    = data.aws_ami.amazon_linux.id
  instance_type               = "m6a.large"
  associate_public_ip_address = true # this should trigger the warning mentioned in the README

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_launch_configuration" "public_ip_association_undeclared" {
  name                        = "tf-launchconf-styra"
  image_id                    = data.aws_ami.amazon_linux.id
  instance_type               = "m6a.large"

  lifecycle {
    create_before_destroy = true
  }
}
