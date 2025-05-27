package library.v1.kubernetes.admission.util.test_v1

import data.library.v1.kubernetes.admission.util.v1

test_reduce_object_blacklist {
	{"b": 2, "c": 3} == v1.reduce_object_blacklist({"a": 1, "b": 2, "c": 3}, {"a"})
	{"b": 2} == v1.reduce_object_blacklist({"a": 1, "b": 2, "c": 3}, {"a", "c"})
	{"b": 2} == v1.reduce_object_blacklist({"a": 1, "b": 2, "c": 3}, {"a", "c", "d"})
	{} == v1.reduce_object_blacklist({"a": 1, "b": 2, "c": 3}, {"a", "c", "d", "b"})
}

test_merge_objects {
	{} == v1.merge_objects({}, {})
	{"a": 1} == v1.merge_objects({}, {"a": 1})
	{"a": 1} == v1.merge_objects({"a": 1}, {})
	{"a": 1, "b": 2} == v1.merge_objects({"a": 1}, {"b": 2})
	{"a": 1, "b": 2, "c": 3} == v1.merge_objects({"a": 1}, {"b": 2, "c": 3})
	{"a": 1, "b": 2, "c": 3} == v1.merge_objects({"a": 1, "b": 2}, {"c": 3})
	{"a": 1, "b": 2, "c": 3, "d": 4} == v1.merge_objects({"a": 1, "b": 2}, {"c": 3, "d": 4})
}
