# SSOSSH

## Installation
`pip install ssossh`

## Description
Generates a SSH Certificate from an OAuth2 compliant cert server.
Intended to improve the user experience for connecting to remote services through the terminal or VSCode without the need for issuing user password.

## Use
Run `ssossh` in a terminal.
When running the first time, you can use `--sshconfig` to add entries to your ssh config.

Options:
`"-c", "--config", default="~/.authservers.json"`  
JSON format config file containing the list of places we can log into

`"-k", "--keypath", default=None`  
Path to store the ssh key (and certificate)

`"--agent", actin="store_true"`  
Use the ssh agent rather than saving the key

`"-a", "--agentsock", default=None`  
SSH Agent socket (eg the value os SSH_AUTH_SOCK variable). Default is to use whatever this terminal is using

`"--setssh", action="store_true"`  
Add an entry to your ssh config

`"--sshconfig", default=os.path.expanduser("~/.ssh/config")`  
The ssh config to modify

`"-y", "--yes", action="store_true"`  
Yes to all
