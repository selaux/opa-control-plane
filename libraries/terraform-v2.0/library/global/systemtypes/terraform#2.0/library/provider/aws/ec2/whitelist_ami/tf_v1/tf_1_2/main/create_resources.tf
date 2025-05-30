terraform {

  required_version = ">= 1.2"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

locals {
  allowed_ami       = "ami-830c94e3"
  denied_ami        = "ami-0022c769"
}

resource "aws_instance" "good_instance_1" {
  ami           = local.allowed_ami
  instance_type = "t2.micro"
}

resource "aws_instance" "bad_instance_1" {
  ami           = local.denied_ami
  instance_type = "t2.micro"
}

resource "aws_launch_template" "good_template_1" {
  image_id      = local.allowed_ami
  instance_type = "t2.micro"
}

resource "aws_launch_template" "bad_template_1" {
  image_id      = local.denied_ami
  instance_type = "t2.micro"
}

resource "aws_launch_configuration" "good_configuration_1" {
  image_id      = local.allowed_ami
  instance_type = "t2.micro"
}

resource "aws_launch_configuration" "bad_configuration_1" {
  image_id      = local.denied_ami
  instance_type = "t2.micro"
}
