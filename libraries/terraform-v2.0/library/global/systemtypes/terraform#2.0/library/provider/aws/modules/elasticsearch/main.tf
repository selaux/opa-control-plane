resource "aws_elasticsearch_domain" "elasticsearch_example" {
    domain_name           = "example-domain"
    elasticsearch_version = "7.10"

    node_to_node_encryption {
        enabled = true
    }

    encrypt_at_rest {
        enabled = true
    }

    ebs_options {
        ebs_enabled = true
        volume_size = 10
    }

    cluster_config {
        instance_type = "r4.large.elasticsearch"
    }

    tags = {
        Domain = "TestDomain"
    }
}
