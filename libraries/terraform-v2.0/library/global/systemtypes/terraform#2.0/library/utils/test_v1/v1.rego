package global.systemtypes["terraform:2.0"].library.utils.test_v1

import data.global.systemtypes["terraform:2.0"].library.utils.v1 as utils
import future.keywords

# Tests for utils.input_includes_requirements

test_input_includes_requirements_empty_resource_actions if {
	filter := {"actions": {"create"}}
	violation := create_violation([])

	utils.input_includes_requirements(filter, violation) == true
}

test_input_includes_requirements_null_resource_actions if {
	filter := {"actions": {"create"}}
	violation := create_violation(null)

	utils.input_includes_requirements(filter, violation) == true
}

test_input_includes_requirements_no_resource_actions if {
	filter := {"actions": {"create"}}
	violation := {"metadata": {"resource": {}}}

	utils.input_includes_requirements(filter, violation) == true
}

test_input_includes_requirements_create_match if {
	filter := {"actions": {"create"}}
	violation := create_violation(["create"])

	utils.input_includes_requirements(filter, violation) == true
}

test_input_includes_requirements_create_no_match if {
	filter := {"actions": {"create"}}
	violations := [
		create_violation(["create", "update"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete", "create"]), # replace
		create_violation(["create", "delete", "read", "no-op", "update"]),
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
	]

	every violation in violations {
		utils.input_includes_requirements(filter, violation) == false
	}
}

test_input_includes_requirements_delete_match if {
	filters := [
		{"actions": {"delete"}},
		{"actions": {"delete", "foo"}},
		{"actions": {"delete", "no-op"}},
	]
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["delete"]),
		create_violation(["delete", "bar"]),
		create_violation(["bar", "delete"]),
		create_violation(["delete", "read", "no-op", "update"]),
	]

	every filter in filters {
		every violation in violations {
			utils.input_includes_requirements(filter, violation) == true
		}
	}
}

test_input_includes_requirements_delete_no_match if {
	filter := {"actions": {"delete"}}
	violations := [
		create_violation(["create", "delete"]), # replace
		create_violation(["delete", "create"]), # replace
		create_violation(["create", "delete", "read", "no-op", "update"]),
		create_violation(["create"]),
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
	]

	every violation in violations {
		utils.input_includes_requirements(filter, violation) == false
	}
}

test_input_includes_requirements_noop_match if {
	filters := [
		{"actions": {"no-op"}},
		{"actions": {"no-op", "foo"}},
	]
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["no-op"]),
		create_violation(["no-op", "bar"]),
		create_violation(["bar", "no-op"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every filter in filters {
		every violation in violations {
			utils.input_includes_requirements(filter, violation) == true
		}
	}
}

test_input_includes_requirements_noop_no_match if {
	filter := {"actions": {"no-op"}}
	violations := [
		create_violation(["create"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete", "create"]), # replace
		create_violation(["delete"]),
		create_violation(["read"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
	]

	every violation in violations {
		utils.input_includes_requirements(filter, violation) == false
	}
}

test_input_includes_requirements_read_match if {
	filters := [
		{"actions": {"read"}},
		{"actions": {"read", "foo"}},
	]
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["read"]),
		create_violation(["read", "bar"]),
		create_violation(["bar", "read"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every filter in filters {
		every violation in violations {
			utils.input_includes_requirements(filter, violation) == true
		}
	}
}

test_input_includes_requirements_read_no_match if {
	filter := {"actions": {"read"}}
	violations := [
		create_violation(["create"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
	]

	every violation in violations {
		utils.input_includes_requirements(filter, violation) == false
	}
}

test_input_includes_requirements_replace_match if {
	filters := [
		{"actions": {"replace"}},
		{"actions": {"replace", "foo"}},
	]
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["create", "delete"]),
		create_violation(["delete", "create"]),
		create_violation(["create", "delete", "bar"]),
		create_violation(["create", "bar", "delete"]),
		create_violation(["bar", "create", "delete"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every filter in filters {
		every violation in violations {
			utils.input_includes_requirements(filter, violation) == true
		}
	}
}

test_input_includes_requirements_replace_no_match if {
	filter := {"actions": {"replace"}}
	violations := [
		create_violation(["create"]),
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["foobar"]),
	]

	every violation in violations {
		utils.input_includes_requirements(filter, violation) == false
	}
}

test_input_includes_requirements_update_match if {
	filters := [
		{"actions": {"update"}},
		{"actions": {"update", "foo"}},
	]
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["update"]),
		create_violation(["update", "bar"]),
		create_violation(["bar", "update"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every filter in filters {
		every violation in violations {
			utils.input_includes_requirements(filter, violation) == true
		}
	}
}

test_input_includes_requirements_update_no_match if {
	filter := {"actions": {"update"}}
	violations := [
		create_violation(["create"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete", "create"]), # replace
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["foobar"]),
	]

	every violation in violations {
		utils.input_includes_requirements(filter, violation) == false
	}
}

# Tests for utils.input_excludes_requirements

test_input_excludes_requirements_create_match if {
	filter := {"actions": {"create"}}
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["create", "delete"]), # replace
		create_violation(["create", "no-op"]),
		create_violation(["create", "foobar"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == true
	}
}

test_input_excludes_requirements_create_no_match if {
	filter := {"actions": {"create"}}
	violations := [create_violation(["create"])]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == false
	}
}

test_input_excludes_requirements_delete_match if {
	filter := {"actions": {"delete"}}
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["create"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete", "create"]), # replace
		create_violation(["delete", "create", "update"]), # replace + known
		create_violation(["delete", "create", "foo"]), # replace + unknown
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
		create_violation(["create", "no-op", "read", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == true
	}
}

test_input_excludes_requirements_delete_no_match if {
	filter := {"actions": {"delete"}}
	violations := [
		create_violation(["delete"]),
		create_violation(["delete", "foo"]),
		create_violation(["foo", "delete"]),
		create_violation(["delete", "read", "no-op", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == false
	}
}

test_input_excludes_requirements_noop_match if {
	filter := {"actions": {"no-op"}}
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["create"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete", "create"]), # replace
		create_violation(["delete"]),
		create_violation(["read"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
		create_violation(["create", "delete", "read", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == true
	}
}

test_input_excludes_requirements_noop_no_match if {
	filter := {"actions": {"no-op"}}
	violations := [
		create_violation(["no-op"]),
		create_violation(["no-op", "foo"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == false
	}
}

test_input_excludes_requirements_read_match if {
	filter := {"actions": {"read"}}
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["create"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete", "create"]), # replace
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
		create_violation(["create", "delete", "no-op", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == true
	}
}

test_input_excludes_requirements_read_no_match if {
	filter := {"actions": {"read"}}
	violations := [
		create_violation(["read"]),
		create_violation(["read", "foo"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == false
	}
}

test_input_excludes_requirements_replace_match if {
	filter := {"actions": {"replace"}}
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["create"]),
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["update"]),
		create_violation(["foobar"]),
		create_violation(["read", "no-op", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == true
	}
}

test_input_excludes_requirements_replace_no_match if {
	filter := {"actions": {"replace"}}
	violations := [
		create_violation(["create", "delete"]),
		create_violation(["create", "delete", "foo"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == false
	}
}

test_input_excludes_requirements_update_match if {
	filter := {"actions": {"update"}}
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["create"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["foobar"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == true
	}
}

test_input_excludes_requirements_update_no_match if {
	filter := {"actions": {"update"}}
	violations := [
		create_violation(["update"]),
		create_violation(["update", "foo"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == false
	}
}

test_input_excludes_requirements_update_match if {
	filter := {"actions": {"update"}}
	violations := [
		create_violation(null),
		create_violation([]),
		create_violation(["create"]),
		create_violation(["create", "delete"]), # replace
		create_violation(["delete", "create"]), # replace
		create_violation(["delete"]),
		create_violation(["no-op"]),
		create_violation(["read"]),
		create_violation(["foobar"]),
		create_violation(["create", "delete", "no-op", "read"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == true
	}
}

test_input_excludes_requirements_update_no_match if {
	filter := {"actions": {"update"}}
	violations := [
		create_violation(["update"]),
		create_violation(["update", "foo"]),
		create_violation(["create", "delete", "read", "no-op", "update"]),
	]

	every violation in violations {
		utils.input_excludes_requirements(filter, violation) == false
	}
}

test_multiple_includes if {
	violations := [
		create_violation_with_id(1, ["create"]),
		create_violation_with_id(2, ["delete"]),
		create_violation_with_id(3, ["create", "delete"]), # replace
		create_violation_with_id(4, ["no-op"]),
		create_violation_with_id(5, ["read"]),
		create_violation_with_id(6, ["update"]),
	]
	cases := [
		{
			"filter": {"actions": {"create"}},
			"expected_matches": {1},
		},
		{
			"filter": {"actions": {"create", "delete"}},
			"expected_matches": {1, 2},
		},
		{
			"filter": {"actions": {"replace"}},
			"expected_matches": {3},
		},
		{
			"filter": {"actions": {"create", "replace"}},
			"expected_matches": {1, 3},
		},
		{
			"filter": {"actions": {"create", "delete", "replace"}},
			"expected_matches": {1, 2, 3},
		},
		{
			"filter": {"actions": {"create", "delete", "replace", "no-op"}},
			"expected_matches": {1, 2, 3, 4},
		},
		{
			"filter": {"actions": {"create", "delete", "replace", "no-op", "read"}},
			"expected_matches": {1, 2, 3, 4, 5},
		},
		{
			"filter": {"actions": {"create", "delete", "replace", "no-op", "read", "update"}},
			"expected_matches": {1, 2, 3, 4, 5, 6},
		},
		{
			"filter": {"actions": {"create", "foobar"}},
			"expected_matches": {1},
		},
	]

	every i, case in cases {
		matches := {violation.id | violation := filter_includes(case.filter, violations)[_]}
		assert_equal(matches, case.expected_matches, sprintf("case %v", [i]))
	}
}

test_multiple_excludes if {
	violations := [
		create_violation_with_id(1, ["create"]),
		create_violation_with_id(2, ["delete"]),
		create_violation_with_id(3, ["create", "delete"]), # replace
		create_violation_with_id(4, ["no-op"]),
		create_violation_with_id(5, ["read"]),
		create_violation_with_id(6, ["update"]),
	]
	cases := [
		{
			"filter": {"actions": {"create"}},
			"expected_matches": {2, 3, 4, 5, 6},
		},
		{
			"filter": {"actions": {"create", "delete"}},
			"expected_matches": {3, 4, 5, 6},
		},
		{
			"filter": {"actions": {"replace"}},
			"expected_matches": {1, 2, 4, 5, 6},
		},
		{
			"filter": {"actions": {"create", "replace"}},
			"expected_matches": {2, 4, 5, 6},
		},
		{
			"filter": {"actions": {"create", "delete", "replace"}},
			"expected_matches": {4, 5, 6},
		},
		{
			"filter": {"actions": {"create", "delete", "replace", "no-op"}},
			"expected_matches": {5, 6},
		},
		{
			"filter": {"actions": {"create", "delete", "replace", "no-op", "read"}},
			"expected_matches": {6},
		},
		{
			"filter": {"actions": {"create", "delete", "replace", "no-op", "read", "update"}},
			"expected_matches": set(),
		},
		{
			"filter": {"actions": {"create", "foobar"}},
			"expected_matches": {2, 3, 4, 5, 6},
		},
	]

	every i, case in cases {
		matches := {violation.id | violation := filter_excludes(case.filter, violations)[_]}
		assert_equal(matches, case.expected_matches, sprintf("case %v", [i]))
	}
}

# Helpers

create_violation(actions) := {"metadata": {"resource": {"actions": actions}}}

create_violation_with_id(id, actions) := {"id": id, "metadata": {"resource": {"actions": actions}}}

filter_includes(filter, violations) := [violation |
	violation := violations[_]
	utils.input_includes_requirements(filter, violation)
]

filter_excludes(filter, violations) := [violation |
	violation := violations[_]
	utils.input_excludes_requirements(filter, violation)
]

assert_equal(actual, expected, note) if {
	actual == expected
} else = false if {
	print(note, "expected:", expected, "got:", actual)
}
