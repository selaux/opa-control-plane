# Create a new load balancer
resource "aws_elb" "sample_elb" {
  name               = "sample-terraform-elb"
  availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]

  access_logs {
    bucket        = aws_s3_bucket.tf_sample_log_s3.bucket
    bucket_prefix = "tfelb"
    interval      = 60
    enabled       = true # Deny, if enabled = false
  }

  listener { # Deny, if listener block not configured with ssl/https
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  listener {
    instance_port      = 8000
    instance_protocol  = "http"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = "arn:aws:iam::123456789012:server-certificate/certName"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "HTTP:8000/"
    interval            = 30
  }

  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true  # Deny, if connection draining is false. Optional value if not added, sets to true
  connection_draining_timeout = 400

  tags = {
    Name = "foobar-terraform-elb"
  }
}