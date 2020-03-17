greetd(1)

# NAME

greetd - A greeter daemon / login manager daemon

# SYNOPSIS

*greetd* [options]

# OPTIONS

*-h, --help*
	Show help message and quit.

*-c, --config <config>*
	Specifies the configuration file to use.

# DESCRIPTION

greetd was created to fill the need for a simple login manager that makes no
assumptions about the applications it starts, thus being equally suitable for
starting console sessions, Wayland sessions, or something else entirely.

greetd does not itself interact with the user, but relies on an external
greeter process like agreety(1) to handle that aspect.

# OPERATION

greetd creates, authenticates and starts *sessions*. When greetd is launched,
as no session is pending start yet, greetd starts the configured *greeter*.

An IPC socket is exposed to this greeter, as reported by *GREETD_SOCK*. The
greeter can use this to create, authenticate and finally start a session. For
more information about the IPC layer, see greetd-ipc(7).

Once the greeter has requested the start of a session and terminated itself,
greetd will start the new session. Once this session terminates, the process
starts over.

greetd makes no assumptions about any sessions, including the greeter. They
can be text-based, running in the active console, or full on graphical
environments.

# CONFIGURATION

greetd looks for a configuration file in /etc/greetd/config.toml by default.
This can be overriden with a command-line argument.

For information on the config file format, see greetd(5).

# AUTHORS

Maintained by Kenny Levinsen <contact@kl.wtf>. For more information about
greetd development, see https://git.sr.ht/~kennylevinsen/greetd.

# SEE ALSO
*greetd*(5) *greetd-ipc*(7)