variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "us-west-2"
}

variable "instance_type" {
  type        = string
  description = "Type of the instance for launch configuration"
  default     = "m6a.large"
}

variable "launch_conf_name" {
  type        = string
  description = "Name of the launch configuration"
  default     = "tf-launchconf-styra"
}

variable "asg_name" {
  type        = string
  description = "Name of the autoscaling group"
  default     = "tf-asg-styra"
}
