resource "aws_opensearch_domain" "example" {
  domain_name           = "opensearch-domain"
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
  tags = {
      Domain = "TestDomain"
  }
}
