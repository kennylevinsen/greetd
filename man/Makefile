SCDOC=$(shell pkg-config --variable=scdoc scdoc)
PREFIX?=/usr/local
MANDIR?=$(PREFIX)/share/man
DESTDIR?=

agreety.1: agreety-1.scd
	$(SCDOC) < agreety-1.scd > agreety.1

greetd.1: greetd-1.scd
	$(SCDOC) < greetd-1.scd > greetd.1

greetd.5: greetd-5.scd
	$(SCDOC) < greetd-5.scd > greetd.5

greetd-ipc.7: greetd-ipc-7.scd
	$(SCDOC) < greetd-ipc-7.scd > greetd-ipc.7

all: agreety.1 greetd.1 greetd.5 greetd-ipc.7

install:
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	mkdir -p $(DESTDIR)$(MANDIR)/man7
	install -m644 agreety.1 $(DESTDIR)$(MANDIR)/man1/agreety.1
	install -m644 greetd.1 $(DESTDIR)$(MANDIR)/man1/greetd.1
	install -m644 greetd.5 $(DESTDIR)$(MANDIR)/man5/greetd.5
	install -m644 greetd-ipc.7 $(DESTDIR)$(MANDIR)/man7/greetd-ipc.7

clean:
	rm -f agreety.1 greetd.1 greetd.5 greetd-ipc.7

.DEFAULT_GOAL=all
.PHONY: all install clean
