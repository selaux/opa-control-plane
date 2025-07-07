package policy["com.styra.envoy.ingress"].main

main = x {
  x := data.library.v1.stacks.results.envoy.ingress.v1.main
    with data.context as {
      "system_type": "envoy"
    }
}
