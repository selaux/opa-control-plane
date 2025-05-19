package library.v1.utils.labels.match.v1

# Characters used to constrain wildcard matching for label and annotation keys
keys_delimiters = ["-", ".", "_", "/"]

# NOTE: ideally keys and values would use the same delimiters.
# However, the addition of a new delimiter "/" to both might break backwards
# compatbility for annotations or label values that use this character in some
# way. Therefore choosing to separate the delimiters into two sets.
values_delimiters = ["-", ".", "_"]

# Returns `true` only if `labels` matches _every_ requirement in `include` _and_
# doesn’t match _any_ requirement in `exclude`.
# regal ignore:rule-shadows-builtin
all(labels, include, exclude) {
	not count(include) == 0
	includes_each(labels, include)
	includes_none(labels, exclude)
}

# Returns `true` if `labels` matches _any_ requirement in `expected_labels`.
# NOTE: This method returns `false` if `expected_labels` is empty.
# This rule works for both labels and annotations
includes_some(labels, expected_labels) {
	count(filter(labels, expected_labels)) > 0
}

# Returns `true` if `labels` matches _every_ requirement in `expected_labels`.
# NOTE: This method returns `true` if `expected_labels` is empty.
includes_each(labels, expected_labels) {
	count(filter(labels, expected_labels)) == count(expected_labels)
}

# Returns `true` if `labels` doesn’t match _any_ requirement in `expected_labels`.
includes_none(labels, expected_labels) {
	count(filter(labels, expected_labels)) == 0
}

# Returns the subset of `labels` matching `requirements`.
filter(labels, requirements) = x {
	x := {key: labels[key] |
		exists(labels, key, requirements[pattern])
		glob.match(pattern, keys_delimiters, key)
	}
}

# Returns `true` IF
# (a) `requirement` is an empty set _and_ `labels` defines `key` OR
# (b) any value in `requirement` glob-matches `labels[key]`.
exists(labels, key, requirement) {
	count(requirement) == 0
	labels[key] = _ # `undefined` if `labels` doesn‘t define `key`.
}

else {
	glob.match(requirement[_], values_delimiters, labels[key])
}
