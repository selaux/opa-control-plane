variable "region" {
  default = "us-west-2"
}

variable "vpc_cidr" {
  default = "178.0.0.0/16"
}

variable "subnet_a_cidr" {
  default = "178.0.10.0/24"
}

variable "subnet_b_cidr" {
  default = "178.0.100.0/24"
}

variable "domain" {
  default = "tf-test"
}
