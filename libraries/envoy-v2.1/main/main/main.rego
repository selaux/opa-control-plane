package main

# Note: we should only need to pass in system_id and then lookup system_type from styra.systems[system_id]
#    except styra.systems is an array and we'd need to walk it.  That would be okay if it only included
#    this system's data, but if it includes all systems on the cluster, that'll be costly.

main = x {
	x := data.global.systemtypes["envoy:2.1"].conflicts.entry.main
}
