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
        "allow_stdio_access": false,
        "working_dir": "/",
        "is_init": false,
    },
    {
        "command": ["python3","WebAttestationReport.py"],
        "env_rules": [
            {
                "pattern": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "strategy": "string",
                "required": false
            },
            {
                "pattern": "PYTHONUNBUFFERED=1",
                "strategy": "string",
                "required": false
            },
            {
                "pattern": "TERM=xterm",
                "strategy": "string",
                "required": false
            }
        ],
        "layers": [
            "37e9dcf799048b7d35ce53584e0984198e1bc3366c3bb5582fd97553d31beb4e",
            "97112ba1d4a2c86c1c15a3e13f606e8fcc0fb1b49154743cadd1f065c42fee5a",
            "1e66649e162d99c4d675d8d8c3af90ece3799b33d24671bc83fe9ea5143daf2f",
            "3413e98a178646d4703ea70b9bff2d4410e606a22062046992cda8c8aedaa387",
            "b99a9ced77c45fc4dc96bac8ea1e4d9bc1d2a66696cc057d3f3cca79dc999702",
            "e7fbe653352d546497c534c629269c4c04f1997f6892bd66c273f0c9753a4de3",
            "04c110e9406d2b57079f1eac4c9c5247747caa3bcaab6d83651de6e7da97cb40",
            "f65ec804a63b85f507ac11d187434ea135a18cdc16202551d8dff292f942fdf0",
            "998fe7a12356e0de0f2ffb4134615b42c9510e281c0ecfc7628c121442544309"],
        "mounts": [],
        "exec_processes": [],
        "signals": [],
        "allow_elevated": true,
        "allow_stdio_access": false,
        "working_dir": "/demo-attestion",
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

create_container := {"metadata": [updateMatches, addStarted, addInit],
                     "env_list": env_list,
                     "allow_stdio_access": allow_stdio_access,
                     "allowed": true} {
    not data.framework.container_started

    can_create_container

    # narrow the matches based upon command, working directory, and
    # mount list
    possible_containers := [container |
        container := data.metadata.matches[input.containerID][_]
        data.framework.workingDirectory_ok(container.working_dir)
        data.framework.command_ok(container.command)
        data.framework.mountList_ok(container.mounts, container.allow_elevated)
    ]

    count(possible_containers) > 0

    # check to see if the environment variables match, dropping
    # them if allowed (and necessary)
    env_list := data.framework.valid_envs_for_all(possible_containers)
    containers := [container |
        container := possible_containers[_]
        data.framework.envList_ok(container.env_rules, env_list)
    ]

    count(containers) > 0

    # we can't do narrowing based on allowing stdio access so at this point
    # every container from the policy that might match this create request
    # must have the same allow stdio value otherwise, we are in an undecidable
    # state
    allow_stdio_access := containers[0].allow_stdio_access
    every c in containers {
        c.allow_stdio_access == allow_stdio_access
    }

    updateMatches := {
        "name": "matches",
        "action": "update",
        "key": input.containerID,
        "value": containers,
    }

    addStarted := {
        "name": "started",
        "action": "add",
        "key": input.containerID,
        "value": true,
    }

    init_containers := [ container | 
        container := containers[_] 
        container.is_init 
    ]
    
    addInit := {
        "name": "init",
        "action": "add",
        "key": input.containerID,
        "value": init_containers
    }
}

mount_device := data.framework.mount_device
unmount_device := data.framework.unmount_device
mount_overlay := data.framework.mount_overlay
unmount_overlay := data.framework.unmount_overlay
exec_in_container := data.framework.exec_in_container
exec_external := data.framework.exec_external
shutdown_container := data.framework.shutdown_container
signal_container_process := data.framework.signal_container_process
plan9_mount := data.framework.plan9_mount
plan9_unmount := data.framework.plan9_unmount
load_fragment := data.framework.load_fragment
reason := {"errors": data.framework.errors}