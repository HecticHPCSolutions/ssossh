# SSOSSH

## Installation
`pip install ssossh`

## Description
Generate a SSH Certificate from an OAuth2 compliant cert server

## Use
    
    parser.add_argument("-c", "--config", default="~/.authservers.json",
                        help="JSON format config file containing the list of places we can log into")
    parser.add_argument("-k", "--keypath", default=None,
                        help="Path to store the ssh key (and certificate)")
    parser.add_argument("-a", "--agentsock", default=None,
                        help="SSH Agent socket (eg the value os SSH_AUTH_SOCK variable). Default is to use whatever this terminal is using")
    parser.add_argument("--setssh", action="store_true",
                        help="Add an entry to your ssh config")
    parser.add_argument("-sc", "--sshconfig", default=os.path.expanduser("~/.ssh/config"),
                        help="The ssh config to modify")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Yes to all")