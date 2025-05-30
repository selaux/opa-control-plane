package global.systemtypes["terraform:2.0"].library.utils.v1

collapse_singletons(obj) = result {
	result := {k: collapse(v) | v := obj[k]}
}

collapse(val) = result {
	is_array(val)
	count(val) == 1
	count({x | x := val[_]; is_object(x)}) == count(val)
	result := val[0]
} else = result {
	result := val
}

all_addrs := {a | a := input.planned_values.root_module.resources[_].address} | {a | a := input.resource_changes[_].address}

planned_values_by_addr[addr] = obj {
	resource := input.planned_values.root_module.resources[_]
	addr := resource.address
	obj := resource
}

resource_changes_by_addr[addr] = obj {
	change := input.resource_changes[_]
	addr := change.address
	obj := change
}

transformed_resources[resource] {
	addr := all_addrs[_]
	pv := object.get(planned_values_by_addr, addr, {})
	rc := object.get(resource_changes_by_addr, addr, {})
	common_fields := {"mode", "name", "provider_name", "type", "address"}
	common := object.union(object.filter(pv, common_fields), object.filter(rc, common_fields))

	pvValues := object.get(pv, "values", {})
	rcValues := object.get(object.get(rc, "change", {}), "after", {})

	resource := object.union(common, {"values": collapse_singletons(object.union_n([pvValues, rcValues]))})
}

parse_cert(values) = result {
	raw := crypto.x509.parse_certificates(values.certificate_body)
	count(raw) == 1
	expiryNS := time.parse_rfc3339_ns(raw[0].NotAfter)
	result := {"certificate_body": {
		"file": "certificate.pem",
		"expiration_date": time.date(expiryNS),
		"rsa_key_bytes": 256, # TODO!
	}}
} else = {}

tf2kics[obj] {
	resource := [r | r := transformed_resources[_]][rawidx]
	file := sprintf("/tfplan/%d/%s", [rawidx, resource.name])
	id := sprintf("%d", [rawidx])
	without_cert := object.remove(resource.values, ["certificate_body"])
	without_nulls := {k: v | v := without_cert[k]; v != null}
	obj_cert := parse_cert(resource.values)
	obj := {
		"file": file,
		"id": id,
		"resource": {resource.type: {resource.name: object.union_n([without_nulls, obj_cert])}},
	}
}

transformed_input := {"document": tf2kics}
