package completions

subjects[s] {
	_ := data.object.users[s]
}

subjects[s] {
	_ := data.object.groups[s]
}

subjects[s] {
	_ := data.object.serviceaccounts[s]
}

resources := [r | _ := data.object.resources[r]]
