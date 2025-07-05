package main

main = validating_webhook

validating_webhook = x {
  x := data.library.v1.stacks.decision.v1.main
    with data.context as {
      "policy": "admission_control",
    }
}
