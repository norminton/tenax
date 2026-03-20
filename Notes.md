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


