## Model
  
User goes to your GitHub repository  
User clones or downloads it  
User installs dependencies  
User runs your Python CLI tool on the Linux host  
  
Tool outputs:  
analysis mode: likely persistence findings, prioritized  
collection mode: persistence-relevant artifacts for human review  
  
So the pieces you need are:  
Python source code  
CLI entrypoint  
README.md  
requirements.txt or pyproject.toml  
.gitignore  
optional sample config  
optional tests  


Git-Structure:
```
linux-persist-hunter/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── setup.py
├── main.py
├── config.yaml
├── docs/
│   ├── methodology.md
│   └── persistence-locations.md
├── hunter/
│   ├── __init__.py
│   ├── cli.py
│   ├── analyzer.py
│   ├── collector.py
│   ├── scoring.py
│   ├── reporter.py
│   ├── utils.py
│   └── checks/
│       ├── __init__.py
│       ├── cron.py
│       ├── systemd.py
│       ├── shell_profiles.py
│       ├── ssh.py
│       ├── rc_local.py
│       ├── initd.py
│       ├── tmp_paths.py
│       ├── sudoers.py
│       ├── ld_preload.py
│       ├── network_hooks.py
│       └── containers.py
├── output/
│   └── .gitkeep
└── tests/
    ├── test_scoring.py
    ├── test_cron.py
    └── test_systemd.py
```

