package conflicts.test

import data.global.systemtypes["terraform:2.0"].conflicts.entry
import future.keywords.in

test_enforce {
	system := {"aws": {"s3": {
		"enforce": {{"message": "foo", "metadata": {"rule": {"id": "bar"}}}},
		"deny": set(),
		"monitor": set(),
		"warn": set(),
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with data.styra.stacks as {}
		with data.self.metadata as metadata
	ans.allowed == false
	ans.outcome.reason.FAIL == {"foo"}
	ans.outcome.reason.WARN == set()
	ans.outcome.decisions.enforce == {{"allowed": false, "message": "foo", "metadata": {"rule": {"id": "bar"}}}}
	ans.outcome.decisions.monitor == set()
}

test_enforce_allowed_true_in_snippet {
	# system returns an enforced rule with allowed=true
	system := {"aws": {"s3": {"enforce": {{
		"message": "foo",
		"allowed": true,
	}}}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with data.styra.stacks as {}
		with data.self.metadata as metadata
	ans.allowed == true
	ans.outcome.reason.FAIL == set()
	ans.outcome.reason.WARN == set()
}

test_monitor {
	system := {"aws": {"s3": {
		"monitor": {{"message": "foo"}},
		"deny": set(),
		"enforce": set(),
		"warn": set(),
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with data.styra.stacks as {}
		with data.self.metadata as metadata
	ans.allowed == true
	ans.outcome.reason.WARN == {"foo"}
	ans.outcome.reason.FAIL == set()
}

test_deny {
	system := {"aws": {"s3": {
		"deny": {{"message": "foo"}},
		"monitor": set(),
		"enforce": set(),
		"warn": set(),
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with data.styra.stacks as {}
		with data.self.metadata as metadata
	ans.allowed == false
	ans.outcome.reason.FAIL == {"foo"}
	ans.outcome.reason.WARN == set()
}

test_warn {
	system := {"aws": {"s3": {
		"warn": {{"message": "foo"}},
		"monitor": set(),
		"enforce": set(),
		"deny": set(),
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with data.styra.stacks as {}
		with data.self.metadata as metadata
	ans.allowed == true
	ans.outcome.reason.WARN == {"foo"}
	ans.outcome.reason.FAIL == set()
}

test_enforcemonitor {
	system := {"aws": {"s3": {
		"enforce": {{"message": "foo"}},
		"deny": set(),
		"monitor": {{"message": "bar"}},
		"warn": set(),
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with data.stacks as {}
		with data.styra.stacks as {}
		with data.self.metadata as metadata
	ans.allowed == false
	ans.outcome.reason.FAIL == {"foo"}
	ans.outcome.reason.WARN == {"bar"}
}

test_empty_stacks {
	applicable_stacks := {"stack1", "stack2"}
	stack1 := {"aws": {"s3": {
		"enforce": set(),
		"deny": set(),
		"monitor": set(),
		"warn": set(),
	}}}
	stack2 := stack1
	system := {"aws": {"s3": {
		"enforce": {{"message": "foo"}},
		"deny": set(),
		"monitor": set(),
		"warn": set(),
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.stacks.stack2.policy as stack2
		with data.policy as system
		with data.self.metadata as metadata

	ans.allowed == false
	ans.outcome.reason.FAIL == {"foo"}
	ans.outcome.reason.WARN == set()
}

test_just_stack {
	applicable_stacks := {"stack1"}
	stack1 := {"aws": {"s3": {
		"enforce": {{"message": "foo"}},
		"deny": {{"message": "bar"}},
		"monitor": {{"message": "baz"}},
		"warn": {{"message": "qux"}},
	}}}
	system := {"aws": {"s3": {}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.policy as system
		with data.self.metadata as metadata
	ans.allowed == false
	ans.outcome.reason.FAIL == {"foo", "bar"}
	ans.outcome.reason.WARN == {"baz", "qux"}
}

test_just_2stacks {
	applicable_stacks := {"stack1", "stack2"}
	stack1 := {"aws": {"s3": {
		"enforce": {{"message": "foo"}},
		"monitor": {{"message": "bar"}},
	}}}
	stack2 := {"aws": {"s3": {
		"enforce": {{"message": "baz"}},
		"monitor": {{"message": "qux"}},
	}}}
	system := {"aws": {"s3": {}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.stacks.stack2.policy as stack2
		with data.policy as system
		with data.self.metadata as metadata
	ans.allowed == false
	ans.outcome.reason.FAIL == {"foo", "baz"}
	ans.outcome.reason.WARN == {"bar", "qux"}
}

test_stacks_system {
	applicable_stacks := {"stack1", "stack2"}
	stack1 := {"aws": {"s3": {
		"enforce": {{"message": "foo"}},
		"monitor": {{"message": "bar"}},
	}}}
	stack2 := {"aws": {"s3": {
		"enforce": {{"message": "baz"}},
		"monitor": {{"message": "qux"}},
	}}}
	system := {"aws": {"s3": {
		"enforce": {{"message": "alpha"}},
		"monitor": {{"message": "beta"}},
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.stacks.stack2.policy as stack2
		with data.policy as system
		with data.self.metadata as metadata
	ans.allowed == false
	ans.outcome.reason.FAIL == {"foo", "baz", "alpha"}
	ans.outcome.reason.WARN == {"bar", "qux", "beta"}
}

test_applicable_stacks {
	ans := entry.applicable_stacks with data.styra.stacks.stack1.config.type as "terraform"
		with data.styra.stacks.stack2.config.type as "terraform"
		with data.styra.stacks.stack3.config.type as "envoy"
		with data.styra.stacks.stack4.config.type as "terraform"
		with data.stacks.stack1.selectors.systems as {"myid", "myid2"}
		with data.stacks.stack2.selectors.systems as {"myid", "myid3"}
		with data.stacks.stack3.selectors.systems as {"myid"}
		with data.stacks.stack4.selectors.systems as {"myid2"}
		with data.self.metadata as {"system_type": "terraform", "system_id": "myid"}
	ans == {"stack1", "stack2", "stack3", "stack4"}  # NOTE(tsandall): only applicable stacks are included in bundle
}

test_canon_decision {
	entry.canonical_decision({"message": "foo"}, true) == {"allowed": true, "message": "foo", "metadata": null}
	entry.canonical_decision({"message": "foo"}, false) == {"allowed": false, "message": "foo", "metadata": null}
	entry.canonical_decision({"message": "foo"}, true) == {"allowed": true, "message": "foo", "metadata": null}
	entry.canonical_decision({"message": "foo"}, false) == {"allowed": false, "message": "foo", "metadata": null}
	entry.canonical_decision({"message": "foo", "allowed": true}, false) == {"allowed": true, "message": "foo", "metadata": null}
	entry.canonical_decision({"message": "foo", "allowed": false}, false) == {"allowed": false, "message": "foo", "metadata": null}
	entry.canonical_decision({"message": "foo", "allowed": true}, true) == {"allowed": true, "message": "foo", "metadata": null}
	entry.canonical_decision({"message": "foo", "allowed": false}, true) == {"allowed": false, "message": "foo", "metadata": null}
	entry.canonical_decision({"message": "foo", "metadata": 42}, true) == {"allowed": true, "message": "foo", "metadata": 42}
}

test_no_exemptions {
	some ex in [
		null,
		{},
		{"rules": null},
		{"rules": {}},
		{"rules": {"foo.bar": null}},
		{"rules": {"foo.bar": {}}},
		{"rules": {"foo.bar": {"targets": null}}},
		{"rules": {"foo.bar": {"targets": {}}}},
	]
	system := {"aws": {"s3": {
		"enforce": {{
			"message": "1",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"deny": {{
			"message": "2",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"monitor": {{
			"message": "3",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"warn": {{
			"message": "4",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
	}}}

	applicable_stacks := {"stack1"}
	stack1 := {"aws": {"s3": {
		"enforce": {{
			"message": "5",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"deny": {{
			"message": "6",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"monitor": {{
			"message": "7",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"warn": {{
			"message": "8",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
	}}}

	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.self.metadata as metadata
		with data.exemptions["exemptions.json"] as ex

	ans.allowed == false
	ans.outcome.reason.FAIL == {"1", "2", "5", "6"}
	ans.outcome.reason.WARN == {"3", "4", "7", "8"}
	ans.outcome.decisions.enforce == {
		{"allowed": false, "message": "1", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "2", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "5", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "6", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
	}
	ans.outcome.decisions.monitor == {
		{"allowed": true, "message": "3", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "4", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "7", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "8", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
	}
	ans.outcome.decisions.exemption == set()
}

test_exemptions_no_expiration {
	ex := {"rules": {"foo.bar": {"targets": {
		"one.two": {"comment": "One Two"},
		"a.b": {"comment": "A B"},
	}}}}

	system := {"aws": {"s3": {
		"enforce": {
			{
				"message": "1", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "2",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "3",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "4"},
		},
		"deny": {
			{
				"message": "5", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "6",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "7",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "8"},
		},
		"monitor": {
			{
				"message": "9", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "10",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "11",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "12"},
		},
		"warn": {
			{
				"message": "13", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "14",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "15",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "16"},
		},
	}}}

	applicable_stacks := {"stack1"}
	stack1 := {"aws": {"s3": {
		"enforce": {
			{
				"message": "17", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "18",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "19",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "20"},
		},
		"deny": {
			{
				"message": "21", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "22",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "23",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "24"},
		},
		"monitor": {
			{
				"message": "25", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "26",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "27",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "28"},
		},
		"warn": {
			{
				"message": "29", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "30",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "31",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "32"},
		},
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.self.metadata as metadata
		with data.exemptions["exemptions.json"] as ex

	ans.allowed == false
	ans.outcome.reason.FAIL == {"2", "3", "4", "6", "7", "8", "18", "19", "20", "22", "23", "24"} # "1", "5", "17", "21" filtered
	ans.outcome.reason.WARN == {"10", "11", "12", "14", "15", "16", "26", "27", "28", "30", "31", "32"} # "9", "13", "25", "29" filtered
	ans.outcome.decisions.enforce == {
		# "1" filtered
		{"allowed": false, "message": "2", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "3", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": false, "message": "4", "metadata": null},
		# "5" filtered
		{"allowed": false, "message": "6", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "7", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": false, "message": "8", "metadata": null},
		# "17" filtered
		{"allowed": false, "message": "18", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "19", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": false, "message": "20", "metadata": null},
		# "21" filtered
		{"allowed": false, "message": "22", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "23", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": false, "message": "24", "metadata": null},
	}
	ans.outcome.decisions.monitor == {
		# "9" filtered
		{"allowed": true, "message": "10", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "11", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": true, "message": "12", "metadata": null},
		# "13" filtered
		{"allowed": true, "message": "14", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "15", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": true, "message": "16", "metadata": null},
		# "25" filtered
		{"allowed": true, "message": "26", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "27", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": true, "message": "28", "metadata": null},
		# "29" filtered
		{"allowed": true, "message": "30", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "31", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": true, "message": "32", "metadata": null},
	}
	ans.outcome.decisions.exemption == {
		{"allowed": false, "exemption": {"comment": "A B"}, "message": "1", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "exemption": {"comment": "A B"}, "message": "5", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "exemption": {"comment": "A B"}, "message": "9", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "exemption": {"comment": "A B"}, "message": "13", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "exemption": {"comment": "A B"}, "message": "17", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "exemption": {"comment": "A B"}, "message": "21", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "exemption": {"comment": "A B"}, "message": "25", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "exemption": {"comment": "A B"}, "message": "29", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
	}
}

test_exemptions_future_expiration {
	ex := {"rules": {"foo.bar": {"targets": {
		"one.two": {"comment": "One Two", "expires": "2050-01-01T12:00:00+10:00"},
		"a.b": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"},
	}}}}

	system := {"aws": {"s3": {
		"enforce": {
			{
				"message": "1", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "2",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "3",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "4"},
		},
		"deny": {
			{
				"message": "5", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "6",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "7",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "8"},
		},
		"monitor": {
			{
				"message": "9", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "10",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "11",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "12"},
		},
		"warn": {
			{
				"message": "13", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "14",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "15",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "16"},
		},
	}}}

	applicable_stacks := {"stack1"}
	stack1 := {"aws": {"s3": {
		"enforce": {
			{
				"message": "17", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "18",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "19",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "20"},
		},
		"deny": {
			{
				"message": "21", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "22",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "23",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "24"},
		},
		"monitor": {
			{
				"message": "25", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "26",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "27",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "28"},
		},
		"warn": {
			{
				"message": "29", # Should be filtered
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "a.b"},
				},
			},
			{
				"message": "30",
				"metadata": {
					"rule": {"id": "foo.bar"},
					"resource": {"address": "no.match"},
				},
			},
			{
				"message": "31",
				"metadata": {
					"rule": {"id": "no.match"},
					"resource": {"address": "a.b"},
				},
			},
			{"message": "32"},
		},
	}}}
	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.self.metadata as metadata
		with data.exemptions["exemptions.json"] as ex

	ans.allowed == false
	ans.outcome.reason.FAIL == {"2", "3", "4", "6", "7", "8", "18", "19", "20", "22", "23", "24"} # "1", "5", "17", "21" filtered
	ans.outcome.reason.WARN == {"10", "11", "12", "14", "15", "16", "26", "27", "28", "30", "31", "32"} # "9", "13", "25", "29" filtered
	ans.outcome.decisions.enforce == {
		# "1" filtered
		{"allowed": false, "message": "2", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "3", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": false, "message": "4", "metadata": null},
		# "5" filtered
		{"allowed": false, "message": "6", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "7", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": false, "message": "8", "metadata": null},
		# "17" filtered
		{"allowed": false, "message": "18", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "19", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": false, "message": "20", "metadata": null},
		# "21" filtered
		{"allowed": false, "message": "22", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "23", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": false, "message": "24", "metadata": null},
	}
	ans.outcome.decisions.monitor == {
		# "9" filtered
		{"allowed": true, "message": "10", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "11", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": true, "message": "12", "metadata": null},
		# "13" filtered
		{"allowed": true, "message": "14", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "15", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": true, "message": "16", "metadata": null},
		# "25" filtered
		{"allowed": true, "message": "26", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "27", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": true, "message": "28", "metadata": null},
		# "29" filtered
		{"allowed": true, "message": "30", "metadata": {"resource": {"address": "no.match"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "31", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "no.match"}}},
		{"allowed": true, "message": "32", "metadata": null},
	}
	ans.outcome.decisions.exemption == {
		{"allowed": false, "exemption": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"}, "message": "1", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "exemption": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"}, "message": "5", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "exemption": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"}, "message": "9", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "exemption": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"}, "message": "13", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "exemption": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"}, "message": "17", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "exemption": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"}, "message": "21", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "exemption": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"}, "message": "25", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "exemption": {"comment": "A B", "expires": "2050-01-01T12:00:00Z"}, "message": "29", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
	}
}

test_expired_exemptions {
	ex := {"rules": {"foo.bar": {"targets": {
		"one.two": {"comment": "One Two", "expires": "2021-01-01T12:00:00+10:00"},
		"a.b": {"comment": "A B", "expires": "2021-01-01T12:00:00Z"},
	}}}}

	system := {"aws": {"s3": {
		"enforce": {{
			"message": "1",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"deny": {{
			"message": "2",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"monitor": {{
			"message": "3",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"warn": {{
			"message": "4",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
	}}}

	applicable_stacks := {"stack1"}
	stack1 := {"aws": {"s3": {
		"enforce": {{
			"message": "5",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"deny": {{
			"message": "6",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"monitor": {{
			"message": "7",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
		"warn": {{
			"message": "8",
			"metadata": {
				"rule": {"id": "foo.bar"},
				"resource": {"address": "a.b"},
			},
		}},
	}}}

	metadata := {"system_type": "foo", "system_id": "bar"}

	ans := entry.main with data.policy as system
		with entry.applicable_stacks as applicable_stacks
		with data.stacks.stack1.policy as stack1
		with data.self.metadata as metadata
		with data.exemptions["exemptions.json"] as ex

	ans.allowed == false
	ans.outcome.reason.FAIL == {"1", "2", "5", "6"}
	ans.outcome.reason.WARN == {"3", "4", "7", "8"}
	ans.outcome.decisions.enforce == {
		{"allowed": false, "message": "1", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "2", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "5", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": false, "message": "6", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
	}
	ans.outcome.decisions.monitor == {
		{"allowed": true, "message": "3", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "4", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "7", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
		{"allowed": true, "message": "8", "metadata": {"resource": {"address": "a.b"}, "rule": {"id": "foo.bar"}}},
	}
	ans.outcome.decisions.exemption == set()
}
