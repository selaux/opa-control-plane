package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.without_imds_v2.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Restrict instances without IMDSv2"
# description: EC2 instances and EC2 Launch templates require Instance Metadata Service Version 2 (IMDSv2) enabled.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.without_imds_v2"
#   impact: ""
#   remediation: ""
#   severity: "medium"
#   resource_category: ""
#   control_category: ""
#   rule_link: "https://docs.styra.com/systems/terraform/snippets"
#   platform:
#     name: "terraform"
#     versions:
#       min: "v0.12"
#       max: "v1.3"
#   provider:
#     name: "aws"
#     versions:
#       min: "v3"
#       max: "v4"
#   rule_targets:
#     - { scope: "resource", service: "ec2", name: "instance", identifier: "aws_instance", argument: "metadata_options.http_endpoint" }
#     - { scope: "resource", service: "ec2", name: "instance", identifier: "aws_instance", argument: "metadata_options.http_tokens" }
#     - { scope: "resource", service: "ec2", name: "launch_template", identifier: "aws_launch_template", argument: "metadata_options.http_endpoint" }
#     - { scope: "resource", service: "ec2", name: "launch_template", identifier: "aws_launch_template", argument: "metadata_options.http_tokens" }
# schema:
#   decision:
#     - type: rego
#       key: allowed
#       value: "false"
#     - type: rego
#       key: message
#       value: "violation.message"
#     - type: rego
#       key: metadata
#       value: "violation.metadata"
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[violation]"
vulnerable_imds_config[violation] {
	vulnerable_imds_configuration[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

# Analyze ec2 instance metadata configurations
vulnerable_imds_configuration[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	not utils.is_key_defined(ec2.change.after, "metadata_options")

	obj := {
		"message": sprintf("EC2 instance %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [ec2.address]),
		"resource": ec2,
		"context": {"metadata_options": "undefined"},
	}
}

vulnerable_imds_configuration[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	metadata_options := ec2.change.after.metadata_options[_]
	not utils.is_key_defined(metadata_options, "http_endpoint")

	obj := {
		"message": sprintf("EC2 instance %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [ec2.address]),
		"resource": ec2,
		"context": {"metadata_options.http_endpoint": "undefined"},
	}
}

vulnerable_imds_configuration[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	ec2.change.after.metadata_options[_].http_endpoint == "disabled"

	obj := {
		"message": sprintf("EC2 instance %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [ec2.address]),
		"resource": ec2,
		"context": {"metadata_options.http_endpoint": "disabled"},
	}
}

vulnerable_imds_configuration[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	metadata_options := ec2.change.after.metadata_options[_]
	not utils.is_key_defined(metadata_options, "http_tokens")

	obj := {
		"message": sprintf("EC2 instance %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [ec2.address]),
		"resource": ec2,
		"context": {"metadata_options.http_tokens": "undefined"},
	}
}

vulnerable_imds_configuration[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	ec2.change.after.metadata_options[_].http_tokens == "optional"

	obj := {
		"message": sprintf("EC2 instance %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [ec2.address]),
		"resource": ec2,
		"context": {"metadata_options.http_tokens": "optional"},
	}
}

# Analyze launch template metadata configurations
vulnerable_imds_configuration[obj] {
	launch_temp := util.launch_template_resource_changes[_]
	not utils.is_key_defined(launch_temp.change.after, "metadata_options")

	obj := {
		"message": sprintf("EC2 launch template %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [launch_temp.address]),
		"resource": launch_temp,
		"context": {"metadata_options": "undefined"},
	}
}

vulnerable_imds_configuration[obj] {
	launch_temp := util.launch_template_resource_changes[_]
	metadata_options := launch_temp.change.after.metadata_options[_]
	not utils.is_key_defined(metadata_options, "http_endpoint")

	obj := {
		"message": sprintf("EC2 launch template %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [launch_temp.address]),
		"resource": launch_temp,
		"context": {"metadata_options.http_endpoint": "undefined"},
	}
}

vulnerable_imds_configuration[obj] {
	launch_temp := util.launch_template_resource_changes[_]
	launch_temp.change.after.metadata_options[_].http_endpoint == "disabled"

	obj := {
		"message": sprintf("EC2 launch template %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [launch_temp.address]),
		"resource": launch_temp,
		"context": {"metadata_options.http_endpoint": "disabled"},
	}
}

vulnerable_imds_configuration[obj] {
	launch_temp := util.launch_template_resource_changes[_]
	metadata_options := launch_temp.change.after.metadata_options[_]
	not utils.is_key_defined(metadata_options, "http_tokens")

	obj := {
		"message": sprintf("EC2 launch template %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [launch_temp.address]),
		"resource": launch_temp,
		"context": {"metadata_options.http_endpoint": "undefined"},
	}
}

vulnerable_imds_configuration[obj] {
	launch_temp := util.launch_template_resource_changes[_]
	launch_temp.change.after.metadata_options[_].http_tokens == "optional"

	obj := {
		"message": sprintf("EC2 launch template %v has Instance Metadata Service Version 2 (IMDSv2) disabled.", [launch_temp.address]),
		"resource": launch_temp,
		"context": {"metadata_options.http_endpoint": "optional"},
	}
}
