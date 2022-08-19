package policy

import future.keywords.every
import future.keywords.in

default mount_device := false
mount_device := true {
    data.framework.mount_device
}

mount_device := true {
    count(data.policy.containers) == 0
	data.policy.allow_all
}

default mount_overlay := false
mount_overlay := true {
    data.framework.mount_overlay
}

mount_overlay := true {
    count(data.policy.containers) == 0
	data.policy.allow_all
}

default create_container := false
create_container := true {
    data.framework.create_container
}

create_container := true {
    count(data.policy.containers) == 0
	data.policy.allow_all
}

default exec_in_container := false
exec_in_container := true {
	data.framework.exec_in_container
}

exec_in_container := true {
	count(data.policy.containers) == 0
	data.policy.allow_all
}

default exec_external := false
exec_external := true {
	data.framework.exec_external
}

exec_external := true {
	count(data.policy.containers) == 0
	data.policy.allow_all
}

# error messages

default container_started := false
container_started := true {
	input.containerID in data.started
}

reason["container already started"] {
	input.rule == "create_container"
	container_started
}

reason["container not started"] {
	input.rule == "exec_in_container"
	not container_started
}

default command_matches := false
command_matches := true {
	input.rule == "create_container"
	some container in data.policy.containers
	data.framework.command_ok(container.command)
}

command_matches := true {
	input.rule == "exec_in_container"
	some container in data.policy.containers
	some process in container.exec_processes
	data.framework.command_ok(process.command)
}

command_matches := true {
	input.rule == "exec_external"
	some process in data.policy.ext_processes
	data.framework.command_ok(process.command)
}

reason["invalid command"] {
	not command_matches
}

default envList_matches := false
envList_matches := true {
	input.rule == "create_container"
	some container in data.policy.containers
	data.framework.envList_ok(container.env_rules)
}

envList_matches := true {
	input.rule == "exec_in_container"
	some container in data.policy.containers
	some process in container.exec_processes
	data.framework.envList_ok(process.env_rules)
}

envList_matches := true {
	input.rule == "exec_external"
	some process in data.policy.ext_processes
	data.framework.envList_ok(process.env_rules)

}

reason["invalid env list"] {
	not envList_matches
}

default workingDirectory_matches := false
workingDirectory_matches := true {
	input.rule == "create_container"
	some container in data.policy.containers
	data.framework.workingDirectory_ok(container.working_dir)
}

workingDirectory_matches := true {
	input.rule == "exec_in_container"
	some container in data.policy.containers
	some process in container.exec_processes
	data.framework.workingDirectory_ok(process.working_dir)
}

workingDirectory_matches := true {
	input.rule == "exec_external"
	some process in data.policy.ext_processes
	data.framework.workingDirectory_ok(process.working_dir)
}

reason["invalid working directory"] {
	not workingDirectory_matches
}

default mountList_matches := false
mountList_matches := true {
	some container in data.policy.containers
	data.framework.mountList_ok(container.mounts)
}

reason["invalid mount list"] {
	input.rule in ["create_container", "exec_in_container"]
	not mountList_matches
}