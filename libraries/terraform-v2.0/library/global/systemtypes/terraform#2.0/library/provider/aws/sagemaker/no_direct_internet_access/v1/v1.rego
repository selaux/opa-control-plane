package global.systemtypes["terraform:2.0"].library.provider.aws.sagemaker.no_direct_internet_access.v1

import data.global.systemtypes["terraform:2.0"].library.provider.aws.util.v1 as util
import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils

# METADATA: library-snippet
# version: v1
# title: "AWS: SageMaker: Prohibit SageMaker Notebook instance with direct internet access enabled"
# description: Require AWS/SageMaker instance to have direct internet access disabled.
# severity: "high"
# platform: "terraform"
# resource-type: "aws-sagemaker"
# custom:
#   id: "aws.sagemaker.no_direct_internet_access"
#   impact: ""
#   remediation: ""
#   severity: "high"
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
#     - { scope: "resource", service: "sagemaker", name: "sagemaker_notebook_instance", identifier: "aws_sagemaker_notebook_instance", argument: "direct_internet_access" }
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
direct_internet_access_disabled[violation] {
	internet_access_disabled[decision]

	violation := {
		"message": decision.message,
		"metadata": utils.build_metadata_return(rego.metadata.rule(), null, decision.resource, decision.context),
	}
}

internet_access_disabled[obj] {
	sagemaker_notebook_instance := util.sagemaker_notebook_instance_resource_changes[_]
	utils.is_key_defined(sagemaker_notebook_instance.change.after, "direct_internet_access")
	not sagemaker_notebook_instance.change.after.direct_internet_access == "Disabled"

	obj := {
		"message": sprintf("AWS SageMaker Notebook instance %v with direct internet access is prohibited.", [sagemaker_notebook_instance.address]),
		"resource": sagemaker_notebook_instance,
		"context": {"direct_internet_access": sagemaker_notebook_instance.change.after.direct_internet_access},
	}
}

internet_access_disabled[obj] {
	sagemaker_notebook_instance := util.sagemaker_notebook_instance_resource_changes[_]
	not utils.is_key_defined(sagemaker_notebook_instance.change.after, "direct_internet_access")

	obj := {
		"message": sprintf("AWS SageMaker Notebook instance %v does not have 'direct_internet_access' defined.", [sagemaker_notebook_instance.address]),
		"resource": sagemaker_notebook_instance,
		"context": {"direct_internet_access": "undefined"},
	}
}
