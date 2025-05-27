package policy["com.styra.kubernetes.validating"].main

main = x {
  x := data.library.v1.stacks.decision.v2.main
    with data.context as {
      "system_type": "kubernetes",
      "policy_type": "validating",
    }
}
