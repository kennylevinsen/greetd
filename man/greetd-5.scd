greetd(5)

# NAME

greetd - configuration file

# DESCRIPTION

greetd uses a simple TOML configuration file to define its behavior.

# CONFIGURATION

The configuration is divided into *sections*. Sections are delimited like so:

```
[section_name]
config_key = value
```

Configuration keys can be integer literals, or quote-delimited strings. The
configuration sections are described below.

## terminal

This section contains terminal configuration.

*vt* = num|"next"|"current"
	The VT to run on. Can be the number of a specific VT, "next" to select the
	next available VT, or "current" to stay wherever greetd was started. The
	specific VT is evaluated at startup, and does not change during the execution
	of greetd.

	If using the current or a specific VT, you must ensure that there are no
	other users of that VT. If using systemd with autovt and getty, conflict
	avoidance can be handled in the service unit with
	"Conflicts=getty@ttyN.service", where N is the VT number.

	Use of a specific VT with appropriate conflict avoidance is recommended.

## general

This section contains general configuration that does not fit in other sections
nor deserved its own section.

*source_profile* = true|false
	Whether or not to source ~/.profile and /etc/profile if present when running
	commands. Defaults to true.

*runfile* = path-to-runfile
  Location of greetd's runfile that is created during the first run to prevent
  the initial session from being run again on session termination or on greetd
  restart.

  This file should be in a location that is cleared during a reboot.

## default_session

This section describes the default session, also referred to as the *greeter*.

*command* = command-line
	The command-line to run to start the default session, e.g. "agreety -c sway".
	The default session is automatically started when no other session is
	running, such as when user session terminate, and when greetd is initially
	started with no initial session configured.

	See *greetd-ipc*(7) for information on how a greeter can create sessions.

*user* = user
	The user to use for running the greeter. Defaults to "greeter".

## initial_session

This optional section describes the initial session, commonly referred to as
"auto-login".

The initial session will only be executed during the first run of greetd since
boot in order to ensure signing out works properly and to prevent security
issues whenever greetd or the greeter exit. This is checked through the
presence of the runfile.

*command* = command-line
	The command-line to run to start the initial session, e.g. "sway". The
	initial session will be run when exactly once when greetd is initially
	launched.

*user* = user
	The user to use for running the initial session.

# EXAMPLES

## Regular setup with agreety and sway

```
[terminal]
vt = 1

[default_session]
command = "agreety -c sway"
```

## Auto-login

```
[terminal]
vt = 1

[default_session]
command = "agreety -c sway"

[initial_session]
command = "sway"
user = "john"
```

# AUTHORS

Maintained by Kenny Levinsen <contact@kl.wtf>. For more information about
greetd development, see https://git.sr.ht/~kennylevinsen/greetd.

# SEE ALSO
*greetd*(1) *greetd-ipc*(7)
