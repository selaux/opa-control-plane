package global.systemtypes["terraform:2.0"].library.provider.aws.kics.dynamodb_vpc_endpoint_wihout_route_table_association.v2

import data.global.systemtypes["terraform:2.0"].library.provider.aws.kics_libs.terraform as tf_lib

dynamodb_vpc_endpoint_wihout_route_table_association_inner[result] {
	resource := input.document[i].resource.aws_vpc_endpoint[name]
	serviceNameSplit := split(resource.service_name, ".")
	serviceNameSplit[count(serviceNameSplit) - 1] == "dynamodb"
	vpcNameRef := split(resource.vpc_id, ".")[1]
	not has_route_association(vpcNameRef)
	result := {"documentId": input.document[i].id, "issueType": "MissingAttribute", "keyActualValue": "Dynamodb VPC Endpoint is not associated with Route Table Association", "keyExpectedValue": "Dynamodb VPC Endpoint should be associated with Route Table Association", "resourceName": tf_lib.get_resource_name(resource, name), "resourceType": "aws_vpc_endpoint", "searchKey": sprintf("aws_vpc_endpoint[%s].vpc_id", [name])}
}

has_route_association(vpcNameRef) {
	route := input.document[j].resource.aws_route_table[routeName]
	split(route.vpc_id, ".")[1] == vpcNameRef

	subnet := input.document[k].resource.aws_subnet[subnetName]
	split(subnet.vpc_id, ".")[1] == vpcNameRef

	routeAssociation := input.document[z].resource.aws_route_table_association[routeAssociationName]
	split(routeAssociation.route_table_id, ".")[1] == routeName
	split(routeAssociation.subnet_id, ".")[1] == subnetName
}

# METADATA: library-snippet
# version: v1
# title: "KICS: Dynamodb VPC Endpoint Without Route Table Association"
# description: >-
#   Dynamodb VPC Endpoint should be associated with Route Table Association
# severity: "medium"
# platform: "terraform"
# resource-type: ""
# custom:
#   id: "aws.kics.dynamodb_vpc_endpoint_wihout_route_table_association"
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
dynamodb_vpc_endpoint_wihout_route_table_association_snippet[violation] {
	dynamodb_vpc_endpoint_wihout_route_table_association_inner[inner] with input as data.global.systemtypes["terraform:2.0"].library.utils.v1.transformed_input
	msg := sprintf("%s: %s, %s", [inner.issueType, inner.keyExpectedValue, inner.keyActualValue])
	violation := {
		"message": msg,
		"metadata": data.global.systemtypes["terraform:2.0"].library.utils.v1.build_metadata_return(rego.metadata.rule(), null, null, null),
	}
}
