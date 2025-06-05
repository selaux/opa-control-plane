package global.systemtypes["entitlements:1.0"].library.transform.ldap.v1

# Acts like object.get(), but treats keys as case insensitive. Becomes
# undefined if the key is ambiguous, or if it has no matches.
must_get_case_insensitive(obj, key) = result {
	values := [v | v := obj[k]; lower(k) == lower(key)]
	count(values) == 1
	result := values[0]
}

# METADATA: transform-snippet
# version: v1
# title: "LDAP to users"
# description: >-
#   Transforms an array of inetOrgPerson records to DAS
#   compatible users definitions.
# datasource:
#   categories:
#    - ldap
#    - http
#    - aws/s3
#    - git/content

inetOrgPerson[id] = attributes {
	in := input[_]
	in.objectClass[_] == "inetOrgPerson"

	id := concat(" ", in.uid)
	attributes := {
		"dn": in.dn._raw,
		"name": concat(" ", in.cn),
		"units": in.dn.ou,
	}
}

# METADATA: transform-snippet
# version: v1
# title: "Active Directory LDAP to users"
# description: >-
#   Transforms an array of Active Directory user records to DAS
#   compatible users definitions.
# datasource:
#   categories:
#    - ldap
#    - http
#    - aws/s3
#    - git/content

activeDirectoryUser[id] = attributes {
	in := input[_]
	lower(in.objectClass[_]) == "user"

	dn := must_get_case_insensitive(in, "dn")

	id := concat(" ", must_get_case_insensitive(in, "ObjectGUID"))
	attributes := {
		"dn": must_get_case_insensitive(dn, "_raw"),
		"name": concat(" ", must_get_case_insensitive(in, "cn")),
		"units": must_get_case_insensitive(dn, "ou"),
	}
}

# METADATA: transform-snippet
# version: v1
# title: "LDAP to groups of users"
# description: >-
#   Transforms LDAP group of names to entitlments-compatible groups.
# datasource:
#   categories:
#    - ldap
#    - http
#    - aws/s3
#    - git/content

groupOfNames[id] = attributes {
	in := input[_]
	in.objectClass[_] == "groupOfNames"

	id := concat(" ", in.uid)
	attributes := {
		"dn": in.dn._raw,
		"name": in.cn[_],
		"users": in.member,
	}
}

# METADATA: transform-snippet
# version: v1
# title: "LDAP to organizational units"
# description: >-
#   Transforms LDAP organizational units to an object-based schema.
# datasource:
#   categories:
#    - ldap
#    - http
#    - aws/s3

organizationalUnit[id] = attributes {
	in := input[_]
	in.objectClass[_] == "organizationalUnit"

	id := concat(" ", in.uid)
	attributes := {
		"dn": in.dn._raw,
		"name": concat(" ", in.ou),
	}
}
