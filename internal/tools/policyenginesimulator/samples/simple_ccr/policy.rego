package policy

api_svn := "0.7.0"

import future.keywords.every
import future.keywords.in

containers := [
    {
        "command": ["/pause"],
        "env_rules": [
            {
                "pattern": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "strategy": "string",
                "required": false
            },
            {
                "pattern": "TERM=xterm",
                "strategy": "string",
                "required": false
            }
        ],
        "layers": ["16b514057a06ad665f92c02863aca074fd5976c755d26bff16365299169e8415"],
        "mounts": [],
        "exec_processes": [],
        "signals": [],
        "allow_elevated": false,
        "allow_stdio_access": false,
        "working_dir": "/",
        "is_init": true,
    },
    {
        "id": "user_0",
        "command": ["bash", "/copy_resolv_conf.sh"],
        "env_rules": [
            {
              "pattern": "IDENTITY_API_VERSION=.+",
              "strategy": "re2"
            },
            {
              "pattern": "IDENTITY_HEADER=.+",
              "strategy": "re2"
            },
            {
              "pattern": "SOURCE_RESOLV_CONF_LOCATION=/etc/resolv.conf",
              "strategy": "string"
            },
            {
              "pattern": "DESTINATION_RESOLV_CONF_LOCATION=/mount/resolvconf/resolv.conf",
              "strategy": "string"
            },
            {
              "pattern": "IDENTITY_SERVER_THUMBPRINT=.+",
              "strategy": "re2"
            },
            {
              "pattern": "HOSTNAME=.+",
              "strategy": "re2"
            },
            {
              "pattern": "TERM=xterm",
              "strategy": "string"
            },
            {
              "pattern": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
              "strategy": "string"
            }
       ],
        "layers": [
            "285cb680a55d09f548d4baa804a663764788619824565685b32b8097cbed3d26",
            "a6a6918c07c85e29e48d4a87c1194781251d5185f682c26f20d6ee4e955a239f",
            "296e5baa5b9ded863ca0170e05cd9ecf4136f86c830a9da906184ab147415c7b",
            "97adfda6943f3af972b9bf4fa684f533f10c023d913d195048fef03f9c3c60fd",
            "606fd6baf5eb1a71fd286aea29672a06bfe55f0007ded92ee73142a37590ed19"
        ],

        "mounts": [
            {
              "destination": "/mount/resolvconf",
              "options": ["rbind", "rshared", "rw"],
              "source": "sandbox:///tmp/atlas/resolvconf/.+",
              "type": "bind"
            }
        ],

        "allow_elevated": true,
        "allow_stdio_access": true,
        "working_dir": "/",
        "is_init": false,
    }    
]

# Check if "input" is an init container by finding at least one matching
# container in data.policy.containers that has is_init flag set
is_init_container {
  possible_containers := [container |
      container := data.policy.containers[_]
      data.framework.workingDirectory_ok(container.working_dir)
      data.framework.command_ok(container.command)
      data.framework.mountList_ok(container.mounts, container.allow_elevated)
      container.is_init
  ]

  count(possible_containers) > 0
}

default can_start_container := false

can_create_container {
  is_init_container
}

can_create_container {
  init_containers := [container | 
    container := data.policy.containers[_]
    container.is_init
  ]
  
  every init_container in init_containers { 
    some started_container in data.metadata.init[_]
    started_container.working_dir == init_container.working_dir
    count(started_container.command) == count(init_container.command)
    every i, arg in started_container.command {
      init_container.command[i] == arg
    }
    count(started_container.layers) == count(init_container.layers)
    every i, layer in started_container.layers {
      init_container.layers[i] == layer
    }
  }
}

create_container :=  {
    "metadata": array.concat(result.metadata, [addInit]),
    "env_list": result.env_list,
    "allow_stdio_access": result.allow_stdio_access,
    "allowed": result.allowed    
  } {
  can_create_container
  result := data.framework.create_container

  init_containers := [ container | 
      container := data.metadata.matches[input.containerID][_] 
      container.is_init 
  ]
  
  addInit := {
      "name": "init",
      "action": "add",
      "key": input.containerID,
      "value": init_containers
  }
}

create_container := {
    "metadata": [addStarted],
    "env_list": input.envList,
    "allow_stdio_access": false,
    "allowed": true    
  } {
  can_create_container
  not input.allow_elevated
  not data.framework.container_started

  # TODO: check that there is a sandboxed overlay mounted for this container

  addStarted := {
      "name": "started",
      "action": "add",
      "key": input.containerID,
      "value": true,
  }
}

mount_device := result { 
  data.framework.deviceHash_ok
  result := data.framework.mount_device
}

mount_device := {"metadata": [addSandboxedDevice], "allowed": true} {
  not data.framework.deviceHash_ok
  addSandboxedDevice := {
      "name": "sandboxed_devices",
      "action": "add",
      "key": input.target,
      "value": input.deviceHash,
  }
}

unmount_device := data.framework.unmount_device

mount_overlay := result { 
  containers := [container |
      container := data.policy.containers[_]
      data.framework.layerPaths_ok(container.layers)
  ]

  count(containers) > 0
  result := data.framework.mount_overlay
}

mount_overlay := {"metadata": [addOverlayTarget], "allowed": true} {
  containers := [container |
      container := data.policy.containers[_]
      data.framework.layerPaths_ok(container.layers)
  ]

  count(containers) == 0

  # TODO: check that the overlay is on top of sandboxed devices 

  addOverlayTarget := {
      "name": "overlayTargets",
      "action": "add",
      "key": input.target,
      "value": true,
  }
}

unmount_overlay := data.framework.unmount_overlay
exec_in_container := data.framework.exec_in_container
exec_external := data.framework.exec_external
shutdown_container := data.framework.shutdown_container
signal_container_process := data.framework.signal_container_process
plan9_mount := data.framework.plan9_mount
plan9_unmount := data.framework.plan9_unmount
load_fragment := data.framework.load_fragment
reason := {"errors": data.framework.errors}