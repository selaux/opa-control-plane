package policy["com.styra.envoy.egress"].main

main = x {
  x := data.library.v1.stacks.results.envoy.egress.v1.main
    with data.context as {
      "system_type": "envoy"
    }
}
