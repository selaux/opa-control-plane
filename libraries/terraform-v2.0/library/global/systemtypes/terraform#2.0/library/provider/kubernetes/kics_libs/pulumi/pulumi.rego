package global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.pulumi

import data.global.systemtypes["terraform:2.0"].library.provider.kubernetes.kics_libs.common as common_lib

getResourceName(resource, logicName) = name {
	resourceNameAtt := pulumiResourcesWithName[resource.Type]
	name := resource.Properties[resourceNameAtt]
} else = name {
	name := common_lib.get_tag_name_if_exists(resource)
} else = name {
	name := logicName
}

pulumiResourcesWithName = {
	"gcp:storage:Bucket": "name",
	"gcp:compute:SSLPolicy": "name",
}
