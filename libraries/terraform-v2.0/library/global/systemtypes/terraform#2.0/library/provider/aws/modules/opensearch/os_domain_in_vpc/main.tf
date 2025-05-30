data "aws_vpc" "selected" {
  id = aws_vpc.app_vpc.id
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_security_group" "os" {
  name        = "${aws_vpc.app_vpc.id}-opensearch-${var.domain}"
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
  aws_service_name = "opensearchservice.amazonaws.com"
}

resource "aws_opensearch_domain" "example" {
  domain_name = "opensearch-domain"

  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
      enabled = true
  }
  cluster_config {
    instance_type = "r4.large.search"
  }
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
  vpc_options {
    subnet_ids = [ aws_subnet.subnet_a.id, aws_subnet.subnet_b.id]

    security_group_ids = [aws_security_group.os.id]
  }
  tags = {
    Domain = "TestDomain"
  }
}