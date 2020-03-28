# greetd

greetd is a minimal and flexible login manager daemon that makes no assumptions about what you want to launch.

Use [gtkgreet](https://git.sr.ht/~kennylevinsen/gtkgreet) to launch [sway](https://github.com/swaywm/sway) if you want a fully graphical session, or use `agreety` to launch a shell if you want a drop-in replacement for `agetty(8)` and `login(1)`.

If you can run it from your shell in a TTY, greetd can start it. If it can be taught to speak a simple JSON-based IPC protocol, then it can be a greeter.

## List of known greetd greeters

- agreety - The simple, text-based greeter living in this repo is a simple example.
- gtkgreet - The flagship graphical, GTK based greeter (xdg-shell or wlr-layer-shell, to be used with something like `cage`)
- dlm - Dumb Login Manager (using fbdev)
- wlgreet - Wayland greeter (using wlr-layer-shell, to be used with something like `sway`)

----

## Installation

### From packages

greetd and a few greeters are available in AUR for Arch Linux.

### Manually from source

```sh
# Compile greetd and agreety.
cargo build --release

# Put things into place
sudo cp target/release/{greetd,agreety} /usr/local/bin/
sudo cp greetd.service /etc/systemd/system/greetd.service
mkdir /etc/greetd
cp config.toml /etc/greetd/config.toml

# Look in the configuration file `/etc/greetd/config.toml` and edit as appropriate.
systemctl enable --now greetd
```

## How do I write my own greeter?

All you need to do is an application that can speak the greetd IPC protocol, which is documented in `greetd-ipc(7)`. See gtkgreet or agreety for inspiration.