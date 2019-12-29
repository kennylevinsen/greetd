# greetd

Generic display manager. Composed of a daemon which:

1. Launches a greeter of your choice.
2. Listens on a socket for a login message.
3. If the credentials are valid, terminates the greeter (if it didn't do so itself) and starts the requested session application.
4. When the session application terminates, the greeter is started once again.

All the greeter of choice needs to do is to be able to write a message to a socket. It could be anything from a simple terminal application to a fully-fledged desktop environment in which one of the applications present a user prompt.

The greeter runs as a configured user, which is supposed to be one with no interesting privileges except for what the greeter itself needs to run.

## Included in the box:

### Binaries

- greetd, the daemon itself
- greetctl, a sample application to issue the login message.
- greet_proto, a protocol library in Rust. Don't worry if you don't use Rust, the protocol is very simple.

### Configuration files

- greeter.pam, a PAM service file that should be put as `/etc/pam.d/greeter`
- config.toml, a configuration file example
- greetd.service, a systemd service file example.

## Installation

- `cp greeter.pam /etc/pam.d/greeter`
- `cp greetd.service /etc/systemd/system/greetd.service`
- `mkdir /etc/greeter`
- `cp config.toml /etc/greeter/config.toml`
- Install a greeter (dlm, gtkgreet, etc.) and configure greetd (`/etc/greeter/config.toml`)
- Start the greetd service.

## Dumb standalone demo

(Requires the pam service installed)

1. echo "exec alacritty" > /tmp/sway-lm-config
2. sudo greetd --vt 4 --greeter "sway --config /tmp/sway-lm-config" --greeter-user $LOGNAME
3. (In the new terminal): greetctl
4. Answer the questions, and the sway greeter will be replaced by whatever you typed if your login is successful.

## Other greeters

- gtkgreet - Simple GTK based greeter (to be used with something like `cage`)
- dlm - Dumb Login Manager (using fbdev)
- wlgreet - Wayland greeter (stale)

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

Attempts to log the user in. The specofied command will be run with the specified environment as the requested user if login is successful. The greeter must exit if the login is a success to permit this to happen.


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

### Exit

Runs an exit action, such as powering the machine off.


```
{
	"type": "exit",
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
	"errorType": "exitError",
	"description": "..."
}
```
