package library.v1.utils.object.v1

# Returns value for `key` from `object` if `key` is present in `object`;
# otherwise, returns value for `key` from `defaults` object.
get(object, key, defaults) = x {
	# Take value from object.
	x := object[key]
}

else = x {
	# Take value from `defaults` if it isn’t present in `object`.
	x := defaults[key]
}

# Returns the set of keys in `object`.
keys(object) = x {
	x := {k | object[k] = _}
}

# Mixes objects `a` and `b` into a new object; if a both `a` and `b` define the
# same key, the key defined by `b` will overwrite the key defined by `a`.
merge(a, b) = x {
	u := keys(a) | keys(b)
	x := {k: v | v := get(b, u[k], a)}
}

# regal ignore:rule-shadows-builtin
contains(e, k) {
	a = e[_]
	a == k
}
