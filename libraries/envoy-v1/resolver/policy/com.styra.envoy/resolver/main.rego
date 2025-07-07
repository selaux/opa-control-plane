package policy["com.styra.envoy"].resolver

envoyPolicyTypes = ["ingress", "egress"]

default type = "ingress"

type = inputType {
    # deprecated (envoy v2 API input)
	envoyPolicyTypes[x] = input.attributes.metadata_context.filter_metadata["envoy.filters.http.header_to_metadata"].fields.policy_type.Kind.StringValue
	inputType := envoyPolicyTypes[x]
}

type = inputType {
    # deprecated (envoy v2 API input) + account for change in marshalling function for opa-envoy v0.24.0+
    # https://github.com/open-policy-agent/opa-envoy-plugin/pull/219
	envoyPolicyTypes[x] = input.attributes.metadata_context.filter_metadata["envoy.filters.http.header_to_metadata"].policy_type
	inputType := envoyPolicyTypes[x]
}

type = inputType {
    # envoy v3 API input
    envoyPolicyTypes[x] = input.attributes.metadataContext.filterMetadata["envoy.filters.http.header_to_metadata"].policy_type
	inputType := envoyPolicyTypes[x]
}

main = x {
	pkg := sprintf("com.styra.envoy.%s", [type])
	x := data.policy[pkg].main.main
}
