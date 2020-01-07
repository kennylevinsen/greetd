# greetd

Generic display manager, capable of anything from text-based login to shell (replacing agetty), to graphical login to a Wayland compositor (replacing GDM/lightdm/...).

## List of known greetd greeters

- agreety - The simple, text-based greeter.
- gtkgreet - Simple GTK based greeter (xdg-shell or wlr-layer-shell, to be used with something like `cage`)
- dlm - Dumb Login Manager (using fbdev)
- wlgreet - Wayland greeter (using wlr-layer-shell, to be used with something like `sway`)

## Overview

greetd is a daemon which:

1. Launches a configured greeter of your choice.
2. Listens on a socket for a login message.
3. If the credentials are valid, terminates the greeter (if it didn't do so itself) and starts the requested session application.
4. When the session application terminates, the greeter is started once again.

All the greeter of choice needs to do is to be able to write a message to a socket. It could be anything from a simple terminal application to a fully-fledged desktop environment in which one of the applications present a user prompt. Of course, the same goes for the session the user logs into.

The greeter runs as a configured user, which is supposed to be one with no interesting privileges except for what the greeter itself needs to run.

## Included in the box:

### Binaries

- greetd, the daemon itself
- agreety, a simple agetty greeter clone.
- greetctl, a WIP tool meant to interact with greetd.
- greet_proto, a protocol library in Rust. Don't worry if you don't use Rust, the protocol is very simple.

### Configuration files

- greeter.pam, a PAM service file that should be put as `/etc/pam.d/greeter`
- config.toml, a configuration file example
- greetd.service, a systemd service file example.

## Installation

- `cp greeter.pam /etc/pam.d/greeter`
- `cp greetd.service /etc/systemd/system/greetd.service`
- `mkdir /etc/greetd`
- `cp config.toml /etc/greetd/config.toml`
- Look in the configuration file `/etc/greetd/config.toml` and edit as appropriate.
- Start the greetd service.

## Dumb standalone demo

(Requires the pam service installed)

1. `sudo greetd --vt next --greeter "agreety" --greeter-user $LOGNAME`
2. Answer the questions (username, password, command), and `agreety` will be replaced by the command you typed if your login is successful. See the `agreety` and `greetd` help texts for more info

# Protocol

```
 ________________________________________________________
|           |             |                    |         |
| magic u32 | version u32 | payload_length u32 | payload |
|___________|_____________|____________________|_________|
```

Magic is always `0xAFBFCFDF`, version is `1`, payload is JSON.

Requests and responses are encoded the same.

## Requests

### Login

Attempts to log the user in. The specified command will be run with the specified environment as the requested user if login is successful. The greeter must exit if the login is a success to permit this to happen.


```
{
	"type": "login",
	"username": "user",
	"password": "password",
	"command": ["sway"],
	"env": {
		"XDG_SESSION_TYPE": "wayland",
		"XDG_SESSION_DESKTOP": "sway",
	}
}
```

## Response

### Success

```
{
	"type": "success",
}
```

### Failure

```
{
	"type": "failure",
	"errorType": "loginError",
	"description": "..."
}
```

### Shutdown

Runs an shutdown action, such as powering the machine off.


```
{
	"type": "shutdown",
	"action": "reboot"
}
```

Available actions are: `poweroff`, `reboot` and `exit` (terminates greetd).

## Response

### Success

```
{
	"type": "success",
}
```

### Failure

```
{
	"type": "failure",
	"errorType": "shutdownError",
	"action": "reboot",
	"description": "..."
}
```
