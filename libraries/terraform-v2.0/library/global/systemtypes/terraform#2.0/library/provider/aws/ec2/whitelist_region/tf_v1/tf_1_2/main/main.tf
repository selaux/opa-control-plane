module "ec2" {
  source = "../../../../../modules/ec2"
  aws_region = var.region
}

variable "region" {
  default = "us-west-2"
}