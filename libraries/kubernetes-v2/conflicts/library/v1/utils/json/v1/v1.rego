package library.v1.utils.json.v1

# Given array of JSON patches create and prepend new patches that create missing paths.
ensure_parent_paths_exist(patches) = result {
	# Convert patches to a set
	paths := {p.path | p := patches[_]}

	# Compute all missing subpaths.
	#    Iterate over all paths and over all subpaths
	#    If subpath doesn't exist, add it to the set after making it a string
	missing_paths := {sprintf("/%s", [concat("/", prefix_path)]) |
		paths[path]
		path_array := split(path, "/")
		path_array[i] # walk over path
		i > 0 # skip initial element

		# array of all elements in path up to i
		prefix_path := [path_array[j] | path_array[j]; j < i; j > 0] # j > 0: skip initial element
		walk_path := [to_walk_element(x) | x := prefix_path[_]]
		not input_path_exists(walk_path) with input as input.request.object
	}

	# Sort paths, to ensure they apply in correct order
	ordered_paths := sort(missing_paths)

	# Return new patches prepended to original patches.
	# Don't forget to prepend all paths with a /
	new_patches := [{"op": "add", "path": p, "value": {}} |
		p := ordered_paths[_]
	]

	result := array.concat(new_patches, patches)
}

# Check that the given @path exists as part of the input object.
input_path_exists(path) {
	walk(input, [path, _])
}

to_walk_element(str) = str {
	not regex.match("^[0-9]+$", str)
}

to_walk_element(str) = x {
	regex.match("^[0-9]+$", str)
	x := to_number(str)
}
