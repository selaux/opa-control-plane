resource "aws_security_group" "ingress_restict_public_access" {
  name        = "good_sg"
  description = "Allow TLS inbound traffic"

  ingress {
    description = "ingress rule 1"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/30","172.16.0.0/24"]
  }
  ingress {
    description = "ingress rule 2"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["192.168.0.0/16","169.254.0.0/16"]
  }
  tags = {
    Name = "ingress_restict_public_access"
  }
}
resource "aws_security_group" "allow_web" {
  name        = "allow_web"
  description = "Allow TLS inbound traffic"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_web"
  }
}

resource "aws_security_group" "disallow_ingress" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"

  tags = {
    Name = "allow_tls"
  }
}

resource "aws_security_group_rule" "s3_gateway_egress" {
  description       = "S3 Gateway Egress"
  type              = "ingress"
  security_group_id = "sg-123456"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.10.0.0/16"]
}
