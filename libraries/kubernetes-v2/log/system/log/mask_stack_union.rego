package system.log

mask[secret] {
	data.stacks[stack_id].selectors.systems["ace44151df234247ab59e9177d02c9cc"]

	data.styra.stacks[stack_id].config.type == "kubernetes"

	data.stacks[stack_id].system.log.mask[secret]
}

drop {
	data.stacks[stack_id].selectors.systems["ace44151df234247ab59e9177d02c9cc"]

	data.styra.stacks[stack_id].config.type == "kubernetes"

	data.stacks[stack_id].system.log.drop
}
