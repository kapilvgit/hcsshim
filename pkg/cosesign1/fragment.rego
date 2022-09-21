package parmafragment

containers := [
  {

        "command": [ "python3", "WebAttestationReport.py" ],
        "env_rules": [
            {
              "strategy": "string",
              "pattern": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            },
            {
              "strategy": "string",
              "pattern": "PYTHONUNBUFFERED=1"
            },
            {
              "strategy": "string",
              "pattern": "TERM=xterm"
            }
        ],
        "layers": [
            "858cc299f2ec9369959bb54b77a6222e32e74073b04151ff2afbe9d2eb14cce6",
            "07a62d61a67e8974670a0325d8f5d01787ca3be4708e4dd1729427fa0d961670",
            "f5726a3e84f606815faa7e4a164ce5a1b47db4b5b6cca34b6f479b7f0d43f998",
            "fdc6c330bab4205266491f4188cb8742702a0e29d1ddf0e35f6008253745e747",
            "15f5212321f806e282687cd42a8a16b079d1fe73696debc5d898396c31f1ccdf",
            "eceaa4fe8d9a5fcbf44e685934c90b169113a40b4edb0b16850fe77c3d1180e1",
            "45495f197324531b1d18a388e79e31e11b8af06f3440c12b7182f968df6a577d",
            "5638ab77cbdbfdc105284fda93509c8bbf580a279f8b332b275e3bc3bb494fb5",
            "cb7cef3375327468466c735d8f8a1add075a71a7a6c6c157d57f68d9f378ce6d"
        ]
        "working_dir": "/demo-attestion",
        "allow_elevated": true
  }
]
