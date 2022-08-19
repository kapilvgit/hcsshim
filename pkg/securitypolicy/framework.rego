package framework

import future.keywords.every
import future.keywords.in

default mount_device := false
mount_device := true {
    some container in data.policy.containers
    some layer in container.layers
    input.deviceHash == layer
}

layerPaths_ok(layers) {
    length := count(layers)
    count(input.layerPaths) == length
    every i, path in input.layerPaths {
        layers[length - i - 1] == data.devices[path]
    }
}

default mount_overlay := false
mount_overlay := true {
    some container in data.policy.containers
    layerPaths_ok(container.layers)
}

command_ok(command) {
    count(input.argList) == count(command)
    every i, arg in input.argList {
        command[i] == arg
    }
}

env_ok(pattern, "string", value) {
    pattern == value
}

env_ok(pattern, "re2", value) {
    regex.match(pattern, value)
}

envList_ok(env_rules) {
    every env in input.envList {
        some rule in env_rules
        env_ok(rule.pattern, rule.strategy, env)
    }
}

workingDirectory_ok(working_dir) {
    input.workingDir == working_dir
}

mountSource_ok(constraint, source) {
    startswith(constraint, data.sandboxPrefix)
    newConstraint := replace(constraint, data.sandboxPrefix, input.sandboxDir)
    regex.match(newConstraint, source)
}

mountSource_ok(constraint, source) {
    startswith(constraint, data.hugePagesPrefix)
    newConstraint := replace(constraint, data.hugePagesPrefix, input.hugePagesDir)
    regex.match(newConstraint, source)
}

mountSource_ok(constraint, source) {
    constraint == source
}

mountConstraint_ok(constraint, mount) {
    mount.type == constraint.type
    mountSource_ok(constraint.source, mount.source)
    mount.destination != ""
    mount.destination == constraint.destination
    every option in mount.options {
        some constraintOption in constraint.options
        option == constraintOption
    }
    every option in constraint.options {
        some mountOption in mount.options
        option == mountOption
    }
}

mount_ok(mounts, mount) {
    some constraint in mounts
    mountConstraint_ok(constraint, mount)
}

mount_ok(mounts, mount) {
    some constraint in data.defaultMounts
    mountConstraint_ok(constraint, mount)
}

mountList_ok(mounts) {
    every mount in input.mounts {
        mount_ok(mounts, mount)
    }
}

default create_container := false
create_container := true {
	not input.containerID in data.started
    some container in data.policy.containers
    layerPaths_ok(container.layers)
    command_ok(container.command)
    envList_ok(container.env_rules)
    workingDirectory_ok(container.working_dir)
    mountList_ok(container.mounts)
}

default exec_in_container := false
exec_in_container := true {
    input.containerID in data.started
    some container in data.policy.containers
    layerPaths_ok(container.layers)
    mountList_ok(container.mounts)
    some process in container.exec_processes
    command_ok(process.command)
    envList_ok(process.env_rules)
    workingDirectory_ok(process.working_dir)
}