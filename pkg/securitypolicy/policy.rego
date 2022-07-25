package policy

import future.keywords.every
import future.keywords.in

default mount_device := false
mount_device := true {
    data.framework.mount_device(data.policy.containers)
}

mount_device := true {
    count(data.policy.containers) == 0
	data.policy.allow_all
}

default mount_overlay := false
mount_overlay := true {
    data.framework.mount_overlay(data.policy.containers)
}

mount_overlay := true {
    count(data.policy.containers) == 0
	data.policy.allow_all
}

default command_matches := false
command_matches := true {
	some container in data.policy.containers
	data.framework.command_ok(container)
}

reason["invalid command"] {
	not command_matches
}

default envList_matches := false
envList_matches := true {
	some container in data.policy.containers
	data.framework.envList_ok(container)
}

reason["invalid env list"] {
	not envList_matches
}

default workingDirectory_matches := false
workingDirectory_matches := true {
	some container in data.policy.containers
	data.framework.workingDirectory_ok(container)
}

reason["invalid working directory"] {
	not workingDirectory_matches
}

default container_started := false
container_started := true {
	input.containerID in data.started
}

reason["container already started"] {
	container_started
}

default create_container := false
create_container := true {
    not container_started
    data.framework.create_container(data.policy.containers)
}

create_container := true {
    count(data.policy.containers) == 0
	data.policy.allow_all
}