package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.ec2_instance_no_public_ip.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Prohibit EC2 instances with a Public IP Address"
# description: Require AWS/EC2 instance to not have a Public IP Address.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.ec2_instance_no_public_ip"
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
#     - { scope: "resource", service: "ec2", name: "instance", identifier: "aws_instance", argument: "associate_public_ip_address" }
#     - { scope: "resource", service: "ec2", name: "launch_template", identifier: "aws_launch_template", argument: "network_interfaces.associate_public_ip_address" }
#     - { scope: "resource", service: "autoscaling_group", "name": "launch_configuration", identifier: "aws_launch_configuration", argument: "associate_public_ip_address" }
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
ec2_instance_with_public_ip[violation] {
	with_public_ip[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

with_public_ip[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	not utils.is_key_defined(ec2.change.after, "associate_public_ip_address")

	obj := {
		"message": sprintf("AWS EC2 instance %v does not have 'associate_public_ip_address' field specified.", [ec2.address]),
		"resource": ec2,
		"context": {"associate_public_ip_address": "undefined"},
	}
}

with_public_ip[obj] {
	ec2 := util.ec2_instance_resource_changes[_]
	ec2.change.after.associate_public_ip_address == true

	obj := {
		"message": sprintf("AWS EC2 instance %v with public IP association enabled is prohibited.", [ec2.address]),
		"resource": ec2,
		"context": {"associate_public_ip_address": true},
	}
}

with_public_ip[obj] {
	launch_template := util.launch_template_resource_changes[_]
	not utils.is_key_defined(launch_template.change.after, "network_interfaces")

	obj := {
		"message": sprintf("AWS EC2 launch template %v does not have 'network_interfaces' field specified.", [launch_template.address]),
		"resource": launch_template,
		"context": {"network_interfaces": "undefined"},
	}
}

with_public_ip[obj] {
	launch_template := util.launch_template_resource_changes[_]
	count(launch_template.change.after.network_interfaces) == 0

	obj := {
		"message": sprintf("AWS EC2 launch template %v does not have 'network_interfaces' defined.", [launch_template.address]),
		"resource": launch_template,
		"context": {"network_interfaces": "undefined"},
	}
}

with_public_ip[obj] {
	launch_template := util.launch_template_resource_changes[_]
	network_interface := launch_template.change.after.network_interfaces[_]
	not utils.is_key_defined(network_interface, "associate_public_ip_address")

	obj := {
		"message": sprintf("AWS EC2 launch template %v does not have 'associate_public_ip_address' field specified.", [launch_template.address]),
		"resource": launch_template,
		"context": {"network_interfaces.associate_public_ip_address": "undefined"},
	}
}

with_public_ip[obj] {
	launch_template := util.launch_template_resource_changes[_]
	launch_template.change.after.network_interfaces[_].associate_public_ip_address == null

	obj := {
		"message": sprintf("AWS EC2 launch template %v with public IP association enabled is prohibited.", [launch_template.address]),
		"resource": launch_template,
		"context": {"network_interfaces.associate_public_ip_address": "undefined"},
	}
}

with_public_ip[obj] {
	launch_template := util.launch_template_resource_changes[_]
	launch_template.change.after.network_interfaces[_].associate_public_ip_address == "true"

	obj := {
		"message": sprintf("AWS EC2 launch template %v with public IP association enabled is prohibited.", [launch_template.address]),
		"resource": launch_template,
		"context": {"network_interfaces.associate_public_ip_address": "true"},
	}
}

with_public_ip[obj] {
	launch_template := util.launch_template_resource_changes[_]
	launch_template.change.after.network_interfaces[_].associate_public_ip_address == true

	obj := {
		"message": sprintf("AWS EC2 launch template %v with public IP association enabled is prohibited.", [launch_template.address]),
		"resource": launch_template,
		"context": {"associate_public_ip_address": true},
	}
}

with_public_ip[obj] {
	launch_configuration := util.launch_configuration_resource_changes[_]
	not utils.is_key_defined(launch_configuration.change.after, "associate_public_ip_address")

	obj := {
		"message": sprintf("AWS EC2 launch configuration %v does not have 'associate_public_ip_address' field specified.", [launch_configuration.address]),
		"resource": launch_configuration,
		"context": {"associate_public_ip_address": "undefined"},
	}
}

with_public_ip[obj] {
	launch_configuration := util.launch_configuration_resource_changes[_]
	launch_configuration.change.after.associate_public_ip_address == true

	obj := {
		"message": sprintf("AWS EC2 launch configuration %v with public IP association enabled is prohibited.", [launch_configuration.address]),
		"resource": launch_configuration,
		"context": {"associate_public_ip_address": true},
	}
}
