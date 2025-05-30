package global.systemtypes["terraform:2.0"].library.provider.aws.s3.whitelisted_ingress_ip.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import data.library.parameters

# METADATA: library-snippet
# version: v1
# title: "AWS: S3: Allow ingress only from whitelisted IP's"
# description: "Require AWS/S3 bucket policy with whitelisted source IP's. To allow all, use wildcard entry '*'."
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-s3"
# custom:
#   id: "aws.s3.whitelisted_ingress_ip"
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
#     - { scope: "resource", service: "s3", name: "bucket", identifier: "aws_s3_bucket", argument: "policy" }
#     - { scope: "resource", service: "s3", name: "bucket_policy", identifier: "aws_s3_bucket_policy", argument: "policy" }
# schema:
#   parameters:
#     - name: allowed_ips
#       label: "A list of allowed IPs"
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
bucket_policy_with_whitelisted_ips[violation] {
	insecure_bucket_policy[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), parameters, decision.resource, decision.context),
	}
}

insecure_bucket_policy[violation] {
	resource := util.s3_bucket_policy_resource_changes[_]
	policy := resource.change.after.policy
	ip := get_ip(policy)
	not ip_allowed(ip)

	violation := {
		"message": sprintf("S3 Bucket Policy %v has an unapproved Source IP: %v.", [resource.address, ip]),
		"resource": resource,
		"context": {"policy": policy},
	}
}

insecure_bucket_policy[violation] {
	resource := util.s3_bucket_resource_changes[_]
	policy := resource.change.after.policy
	ip := get_ip(policy)
	not ip_allowed(ip)

	violation := {
		"message": sprintf("S3 Bucket %v Policy has an unapproved Source IP: %v.", [resource.address, ip]),
		"resource": resource,
		"context": {"policy": policy},
	}
}

get_ip(bucket_policy) := ip {
	policy := json.unmarshal(bucket_policy)
	policy.Statement[i].Effect == "Deny"
	ip := policy.Statement[i].Condition.NotIpAddress["aws:SourceIp"]
}

ip_allowed(ip) {
	parameters.allowed_ips[_] != "*"
	ip == parameters.allowed_ips[_]
}

ip_allowed(ip) {
	parameters.allowed_ips[_] == "*"
}
