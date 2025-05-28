package policy["com.styra.kubernetes.mutating"].main

main = x {
  x := data.library.v1.stacks.decision.v2.main
    with data.context as {
      "system_type": "kubernetes",
      "policy_type": "mutating",
    }
}
