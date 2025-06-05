package main

# Note: we should only need to pass in system_id and then lookup system_type from styra.systems[system_id]
#    except styra.systems is an array and we'd need to walk it.  That would be okay if it only included
#    this system's data, but if it includes all systems on the cluster, that'll be costly.

newinput = data.transform.newinput.newinput {
	true
} else = input {
	true
}

# handle case for tests where input is undefined

else = {}

main = x {
	x := data.global.systemtypes["entitlements:1.0"].conflicts.entry.main with input as newinput
}
