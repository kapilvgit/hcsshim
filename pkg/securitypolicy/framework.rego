package framework

import future.keywords.every
import future.keywords.in

svn := {
	"major": 0,
	"minor": 1,
	"patch": 0,
}

mount_device(containers) {
    some container in containers
    some layer in container.layers
    input.deviceHash == layer
}

layerPaths_ok(container) {
	length := count(container.layers)
    count(input.layerPaths) == length
    every i, path in input.layerPaths {
        container.layers[length - i - 1] == data.devices[path]
    }
}

mount_overlay(containers) {
    some container in containers
	layerPaths_ok(container)
}


command_ok(container) {
    count(input.argList) == count(container.command)
    every i, arg in input.argList {
        container.command[i] == arg
    }
}

env_ok(pattern, "string", value) {
    pattern == value
}

env_ok(pattern, "re2", value) {
    regex.match(pattern, value)
}

rule_ok(rule, envList) {
    not rule.required
}

rule_ok(rule, envList) {
    some env in input.envList
    env_ok(rule.pattern, rule.strategy, env)
}

envList_ok(container) {
    every env in input.envList {
        some rule in container.env_rules
        env_ok(rule.pattern, rule.strategy, env)
    }

    every rule in container.env_rules {
        rule_ok(rule, input.envList)
    }
}

workingDirectory_ok(container) {
	input.workingDir == container.working_dir
}

create_container(containers) {
    some container in containers
	layerPaths_ok(container)
    command_ok(container)
    envList_ok(container)
	workingDirectory_ok(container)
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

mountConstraint_ok(constraint, mount) {
	mount.type == constraint.type
	mountSource_ok(constraint.source, mount.source)
	mount.destination != ""
	mount.destination == constraint.destination
	every option in mount.options {
		some constraintOption in constraint.options
		option == constraintOption
	}
}

mount_ok(container, mount) {
	some constraint in container.mounts
    mountConstraint_ok(constraint, mount)
}

mount_ok(container, mount) {
    some constraint in data.defaultMounts
    mountConstraint_ok(constraint, mount)
}

mountList_ok(container) {
    every mount in input.mounts {
        mount_ok(container, mount)
    }
}

mount(containers) {
    some container in containers
	layerPaths_ok(container)
    command_ok(container)
    envList_ok(container)
	workingDirectory_ok(container)
	mountList_ok(container)
}