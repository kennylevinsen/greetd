greetd(1)

# NAME

greetd - A login manager daemon

# SYNOPSIS

*greetd* [options]

# OPTIONS

*-h, --help*
	Show help message and quit.

*-c, --config <config>*
	Specifies the configuration file to use.

*--vt <vt>*
	The VT to use, overwriting the value from the configuration file. This
	can be useful when starting an instance per VT if greetd cannot deduce
	the intended VT from an associated controlling terminal.

# DESCRIPTION

greetd was created to fill the need for a simple login manager that makes no
assumptions about the applications it starts, thus being equally suitable for
starting console sessions, Wayland sessions, or something else entirely.

greetd does not itself interact with the user, but relies on an external
greeter process like agreety(1) to handle that aspect.

# OPERATION

greetd operates on *sessions*. A greeter creates a session, attempts to
authenticate a user in it, and finally, uses it start an arbitrary
application.

There are two types of preconfigured sessions: The default session, also known
as the *greeter*, and the optional initial session, serving the purpose of
"auto-login". The initial session, if configured, is started once when greetd
launches. The default session is started on launch if an initial session is
not configured, and started again whenever no session is running, such as when
the user logs out.

An IPC socket is exposed to this greeter, as reported by *GREETD_SOCK*. The
greeter can use this to create, authenticate and finally start a session. For
more information about the IPC layer, see greetd-ipc(7).

Once the greeter has requested the start of a session and terminated itself,
greetd will start the new session. Once this session terminates, the process
starts over.

greetd makes no assumptions about any sessions, including the greeter. They
can be text-based, running in the active console, or full-on graphical
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
