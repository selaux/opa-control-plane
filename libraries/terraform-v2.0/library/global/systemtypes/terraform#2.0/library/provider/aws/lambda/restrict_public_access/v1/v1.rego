package global.systemtypes["terraform:2.0"].library.provider.aws.lambda.restrict_public_access.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: Lambda: Prohibit publicly accessible Lambda functions"
# description: Requires AWS/Lambda Function Permissions to include an AWS account ID principal, principal_org_id, source_account AWS account ID, or source_arn resource ARN to prevent public access.
# severity: "medium"
# platform: "terraform"
# resource-type: "aws-lambda"
# custom:
#   id: "aws.lambda.restrict_public_access"
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
#     - { scope: "resource", service: "lambda", name: "lambda_permission", identifier: "aws_lambda_permission", argument: "principal" }
#     - { scope: "resource", service: "lambda", name: "lambda_permission", identifier: "aws_lambda_permission", argument: "principal_org_id" }
#     - { scope: "resource", service: "lambda", name: "lambda_permission", identifier: "aws_lambda_permission", argument: "source_account" }
#     - { scope: "resource", service: "lambda", name: "lambda_permission", identifier: "aws_lambda_permission", argument: "source_arn" }
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
prohibit_lambda_function_with_public_access[violation] {
	publicly_accessible_lambda_permission[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

publicly_accessible_lambda_permission[obj] {
	resource := util.lambda_permission_resource_changes[_]
	resource.change.after.principal != "s3.amazonaws.com"
	resource.change.after.principal != "ses.amazonaws.com"
	regex_for_aws_account := `^\d{12}$`
	resource.change.after.source_account == null
	resource.change.after.source_arn == null
	not regex.match(regex_for_aws_account, resource.change.after.principal)
	principal_org_id_invalid(resource)

	obj := {
		"message": sprintf("AWS Lambda Permission providing public access to Lambda Function %v is prohibited.", [resource.change.after.function_name]),
		"resource": resource,
		"context": {"principal": resource.change.after.principal},
	}
}

publicly_accessible_lambda_permission[obj] {
	resource := util.lambda_permission_resource_changes[_]
	resource.change.after.principal == "s3.amazonaws.com"
	principal_org_id_invalid(resource)
	resource.change.after.source_account == null

	obj := {
		"message": sprintf("AWS Lambda Permission providing public access to Lambda Function %v is prohibited.", [resource.change.after.function_name]),
		"resource": resource,
		"context": {"source_account": "undefined"},
	}
}

publicly_accessible_lambda_permission[obj] {
	resource := util.lambda_permission_resource_changes[_]
	resource.change.after.principal == "ses.amazonaws.com"
	principal_org_id_invalid(resource)
	resource.change.after.source_account == null

	obj := {
		"message": sprintf("AWS Lambda Permission providing public access to Lambda Function %v is prohibited.", [resource.change.after.function_name]),
		"resource": resource,
		"context": {"source_account": "undefined"},
	}
}

principal_org_id_invalid(resource) {
	not resource.change.after.principal_org_id
}

principal_org_id_invalid(resource) {
	regex_for_principal_org_id := `^o-[a-z0-9]{10,32}$`
	not regex.match(regex_for_principal_org_id, resource.change.after.principal_org_id)
}

principal_org_id_invalid(resource) {
	resource.change.after.principal_org_id == null
}
