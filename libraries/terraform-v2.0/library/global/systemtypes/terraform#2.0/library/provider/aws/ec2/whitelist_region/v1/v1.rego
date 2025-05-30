package global.systemtypes["terraform:2.0"].library.provider.aws.ec2.whitelist_region.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import data.library.parameters

# METADATA: library-snippet
# version: v1
# title: "AWS: EC2: Restrict instances with unapproved Regions"
# description: Require EC2 instances to use an AWS Region from a pre-approved list.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-ec2"
# custom:
#   id: "aws.ec2.whitelist_region"
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
#     - { scope: "resource", service: "ec2", name: "instance", identifier: "aws_instance", argument: "region" }
#     - { scope: "provider", provider: "aws", argument: "region" }
# schema:
#   parameters:
#     - name: allowed_regions
#       label: "A list of AWS regions (eg., us-east-1, us-west-2)"
#       type: set_of_strings
#       required: true
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
ec2_whitelist_region[violation] {
	ec2_resources[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), parameters, decision.resource, decision.context),
	}
}

# Scenario 1
# Region has been provided as a constant value
ec2_resources[obj] {
	# Check for EC2 instance in resource changes
	ec2 := util.ec2_instance_resource_changes[_]
	module := utils.module_type(ec2)

	# Check for the same ec2 instance in configuration
	ec2_conf := util.ec2_instance_conf_resources[_]
	utils.module_type(ec2_conf) == module
	ec2_conf.name == ec2.name

	# Fetch the provider configuration which is applicable for the above ec2 instance
	provider_config_key := ec2_conf.provider_config_key
	provider_configuration := input.configuration.provider_config[provider_config_key]

	# Fetch the planned region
	planned_region := provider_configuration.expressions.region.constant_value

	# Check if the planned region is whitelisted or not
	not region_whitelisted(planned_region)

	obj := {
		"message": sprintf("EC2 instance %v uses an unapproved region %v.", [ec2.address, planned_region]),
		"resource": ec2,
		"context": {"region": planned_region},
	}
}

# Scenario 2
# Region has been passed as a variable
ec2_resources[obj] {
	# Check for EC2 instance in resource changes
	ec2 := util.ec2_instance_resource_changes[_]
	module := utils.module_type(ec2)

	# Check for the same ec2 instance in configuration
	ec2_conf := util.ec2_instance_conf_resources[_]
	utils.module_type(ec2_conf) == module
	ec2_conf.name == ec2.name

	# Fetch the provider configuration which is applicable for the above ec2 instance
	provider_config_key := ec2_conf.provider_config_key
	provider_configuration := input.configuration.provider_config[provider_config_key]

	# Fetch the planned region
	region_reference_variable := provider_configuration.expressions.region.references[_]
	region_reference_variable_name := split(region_reference_variable, ".")[1]
	planned_region := input.variables[region_reference_variable_name].value

	# Check if the planned region is whitelisted or not
	not region_whitelisted(planned_region)

	obj := {
		"message": sprintf("EC2 instance %v uses an unapproved region %v.", [ec2.address, planned_region]),
		"resource": ec2,
		"context": {"region": planned_region},
	}
}

region_whitelisted(region) {
	region == parameters.allowed_regions[_]
}
