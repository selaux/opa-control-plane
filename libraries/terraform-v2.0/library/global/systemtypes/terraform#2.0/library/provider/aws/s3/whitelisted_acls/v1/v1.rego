package global.systemtypes["terraform:2.0"].library.provider.aws.s3.whitelisted_acls.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import data.library.parameters
import future.keywords.in

# METADATA: library-snippet
# version: v1
# title: "AWS: S3: Restrict S3 buckets with unapproved ACL"
# description: "Require AWS/S3 to use Canned ACL from a pre-approved list."
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-s3"
# custom:
#   id: "aws.s3.whitelisted_acls"
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
#     - { scope: "resource", service: "s3", name: "bucket", identifier: "aws_s3_bucket", argument: "acl" }
#     - { scope: "resource", service: "s3", name: "bucket_acl", identifier: "aws_s3_bucket_acl", argument: "acl" }
# schema:
#   parameters:
#     - name: allowed_acls
#       label: "A list of ACLs"
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
whitelist_s3_acls[violation] {
	invalid_acls[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), parameters, decision.resource, decision.context),
	}
}

invalid_acls[violation] {
	resource := util.s3_bucket_resource_changes[_]
	acl := resource.change.after.acl
	not is_acl_valid(acl)

	violation := {
		"message": sprintf("S3 bucket %v has an unapproved canned ACL: %v.", [resource.address, acl]),
		"resource": resource,
		"context": {"acl": acl},
	}
}

invalid_acls[violation] {
	resource := util.s3_bucket_acl_resource_changes[_]
	acl := resource.change.after.acl
	not is_acl_valid(acl)

	violation := {
		"message": sprintf("S3 Bucket ACL %v has an unapproved canned ACL: %v.", [resource.address, acl]),
		"resource": resource,
		"context": {"acl": acl},
	}
}

is_acl_valid(s3_acl) {
	s3_acl in parameters.allowed_acls
}
