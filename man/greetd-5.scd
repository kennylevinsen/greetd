greetd(5)

# NAME

greetd - configuration file

# DESCRIPTION

greetd uses a simple TOML configuration file to define its behavior.

# CONFIGURATION

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

*greeter* = command-line
	The command-line to run to start the greeter, e.g. "agreety -c sway". The
	greeter will be run when greetd is initially launched, and every time a
	created session terminates.

	See *greetd-ipc*(7) for information on how a greeter can create sessions.

*greeter_user* = user
	The user to use for running the greeter. Defaults to "greeter".

# AUTHORS

Maintained by Kenny Levinsen <contact@kl.wtf>. For more information about
greetd development, see https://git.sr.ht/~kennylevinsen/greetd.

# SEE ALSO
*greetd*(1) *greetd-ipc*(7)