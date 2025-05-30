data "aws_vpc" "selected" {
  id = aws_vpc.app_vpc.id
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_security_group" "es" {
  name        = "${aws_vpc.app_vpc.id}-elasticsearch-${var.domain}"
  description = "Managed by Terraform"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"

    cidr_blocks = [
      data.aws_vpc.selected.cidr_block,
    ]
  }
}

resource "aws_iam_service_linked_role" "es" {
  aws_service_name = "es.amazonaws.com"
}

resource "aws_elasticsearch_domain" "es" {
  domain_name           = var.domain
  elasticsearch_version = "6.3"

  cluster_config {
    instance_count         = 2 
    instance_type          = "m4.large.elasticsearch"
    zone_awareness_enabled = true
  }

  vpc_options {
    subnet_ids = [ aws_subnet.subnet_a.id, aws_subnet.subnet_b.id]

    security_group_ids = [aws_security_group.es.id]
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
  }

  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
  }

  access_policies = <<CONFIG
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "es:*",
            "Principal": "*",
            "Effect": "Allow",
            "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.domain}/*"
        }
    ]
}
CONFIG

  tags = {
    Domain = "TestDomain"
  }

  depends_on = [aws_iam_service_linked_role.es]
}