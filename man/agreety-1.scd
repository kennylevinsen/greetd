agreety(1)

# NAME

agreety - A text-based greeter for greetd

# SYNOPSIS

*agreety* [options]

# OPTIONS

*-h, --help*
	Show help message and quit.

*-c, --cmd <command>*
	Specifies the command to run on successful login. agreety will ask if none is
	specified.

*-f, --max-failures <num>*
	Specifies the maximum number of login failures to accept before terminating.
	Defaults to 5.

*-u, --user <user>*
	Restrict login to *user*.

# DESCRIPTION

agreety is a very simple text-based greeter, with an appearance similar to
*agetty*(8) and *login*(1). It is bundled with *greetd*(1).

To use agreety, configure it as your greeter in your greetd config file.

# AUTHORS

Maintained by Kenny Levinsen <contact@kl.wtf>. For more information about
greetd development, see https://git.sr.ht/~kennylevinsen/greetd.

# SEE ALSO
*greetd*(1) *greetd*(5)
