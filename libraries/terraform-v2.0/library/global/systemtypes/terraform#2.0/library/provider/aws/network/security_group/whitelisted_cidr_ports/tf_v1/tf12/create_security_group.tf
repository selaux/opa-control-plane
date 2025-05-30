provider "aws" {
  region = "us-west-1"
}

resource "aws_security_group" "good_allow_web" {
  name        = "good_allow_web"
  description = "Allow TLS inbound traffic"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.1.0.0/24", "20.1.0.0/16"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["172.68.0.0/16"]
  }

  tags = {
    Name = "good_allow_web"
  }
}

resource "aws_security_group" "good_disallow_ingress" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"

  tags = {
    Name = "allow_tls"
  }
}

resource "aws_security_group" "blank_group" {
  name = "blank_group"
}

resource "aws_security_group_rule" "good_allow_web_80" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["10.1.0.0/24", "20.1.0.0/16"]
  security_group_id = aws_security_group.blank_group.id
}

resource "aws_security_group_rule" "good_allow_web_443" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["172.68.0.0/16"]
  security_group_id = aws_security_group.blank_group.id
}
