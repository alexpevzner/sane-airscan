CONFDIR = /etc/sane.d
LIBDIR := $(shell pkg-config --variable=libdir sane-backends)
BACKEND = libsane-airscan.so.1
MANDIR = /usr/share/man/
MANPAGE = sane-airscan.5

SRC	= \
	airscan.c \
	airscan-array.c \
	airscan-conf.c \
	airscan-devcaps.c \
	airscan-device.c \
	airscan-devops.c \
	airscan-eloop.c \
	airscan-http.c \
	airscan-jpeg.c \
	airscan-log.c \
	airscan-math.c \
	airscan-opt.c \
	airscan-pollable.c \
	airscan-trace.c \
	airscan-xml.c \
	airscan-zeroconf.c \
	sane_strstatus.c

CFLAGS	= -O2 -g -W -Wall -Werror -fPIC
CFLAGS += `pkg-config --cflags --libs avahi-client`
CFLAGS += `pkg-config --cflags --libs avahi-glib`
CFLAGS += `pkg-config --cflags --libs libjpeg`
CFLAGS += `pkg-config --cflags --libs libsoup-2.4`
CFLAGS += `pkg-config --cflags --libs libxml-2.0`
CFLAGS += -Wl,--version-script=airscan.sym

# Merge DESTDIR and PREFIX
PREFIX := $(abspath $(DESTDIR)/$(PREFIX))
ifeq ($(PREFIX),/)
	PREFIX :=
endif

# This magic is a workaround for libsoup bug.
#
# We are linked against libsoup. If SANE backend goes unloaded
# from the memory, all libraries it is linked against also will
# be unloaded (unless main program uses them directly).
#
# Libsoup, unfortunately, doesn't unload correctly, leaving its
# types registered in GLIB. Which sooner or later leads program to
# crash
#
# The workaround is to prevent our backend's shared object from being
# unloaded when not longer in use, and these magical options do it
# by adding NODELETE flag to the resulting ELF shared object
CFLAGS += -Wl,-z,nodelete

all:	$(BACKEND) test

$(BACKEND): Makefile $(SRC) airscan.h airscan.sym
	-ctags -R .
	gcc -o $(BACKEND) -shared $(SRC) ${CFLAGS}

install: all
	mkdir -p $(PREFIX)$(CONFDIR)
	mkdir -p $(PREFIX)$(CONFDIR)/dll.d
	cp -n airscan.conf $(PREFIX)$(CONFDIR)
	cp -n dll.conf $(PREFIX)$(CONFDIR)/dll.d/airscan
	install -s -D -t $(PREFIX)$(LIBDIR)/sane $(BACKEND)
	mkdir -p $(PREFIX)/$(MANDIR)/man5
	gzip <$(MANPAGE) > $(PREFIX)$(MANDIR)/man5/$(MANPAGE).gz

clean:
	rm -f test $(BACKEND) tags

test:	$(BACKEND) test.c
	gcc -o test test.c $(BACKEND) -Wl,-rpath . ${CFLAGS}
