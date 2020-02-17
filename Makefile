# USER-SETTABLE VARIABLES
#
# The following variables can be overridden by user (i.e.,
# make install DESTDIR=/tmp/xxx):
#
#   Name     Default                  Description
#   ----     -------                  -----------
#   DESTDIR                           Destination directory for make install
#   PREFIX       	              Non-standard: appended to DESTDIR
#   CC       gcc                      C compiler
#   CPPFLAGS                          C preprocessor flags
#   CFLAGS   -O2 -g -W -Wall -Werror  C compiler flags
#   LDFLAGS                           Linker flags
#   COMPRESS gzip                     Program to compress man page, or ""
#   MANDIR   /usr/share/man/          Where to install man page

CC	= gcc
COMPRESS = gzip
CFLAGS	= -O2 -g -W -Wall -Werror
MANDIR	= /usr/share/man/

# These variables are not intended to be user-settable
CONFDIR = /etc/sane.d
LIBDIR := $(shell pkg-config --variable=libdir sane-backends)
BACKEND = libsane-airscan.so.1
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
	airscan-ip.c \
	airscan-jpeg.c \
	airscan-log.c \
	airscan-math.c \
	airscan-netif.c \
	airscan-opt.c \
	airscan-pollable.c \
	airscan-trace.c \
	airscan-uuid.c \
	airscan-xml.c \
	airscan-zeroconf.c \
	airscan-wsdd.c \
	sane_strstatus.c

# Obtain CFLAGS for libraries
airscan_CFLAGS	= $(CFLAGS)
airscan_CFLAGS += -fPIC
airscan_CFLAGS += `pkg-config --cflags --libs avahi-client`
airscan_CFLAGS += `pkg-config --cflags --libs avahi-glib`
airscan_CFLAGS += `pkg-config --cflags --libs libjpeg`
airscan_CFLAGS += `pkg-config --cflags --libs libsoup-2.4`
airscan_CFLAGS += `pkg-config --cflags --libs libxml-2.0`
airscan_CFLAGS += -Wl,--version-script=airscan.sym

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
airscan_CFLAGS += -Wl,-z,nodelete

all:	$(BACKEND) test

$(BACKEND): Makefile $(SRC) airscan.h airscan.sym
	-ctags -R .
	$(CC) -o $(BACKEND) -shared $(CPPFLAGS) $(SRC) $(airscan_CFLAGS) $(LDFLAGS)

install: all
	mkdir -p $(PREFIX)$(CONFDIR)
	mkdir -p $(PREFIX)$(CONFDIR)/dll.d
	cp -n airscan.conf $(PREFIX)$(CONFDIR)
	cp -n dll.conf $(PREFIX)$(CONFDIR)/dll.d/airscan
	install -s -D -t $(PREFIX)$(LIBDIR)/sane $(BACKEND)
	mkdir -p $(PREFIX)/$(MANDIR)/man5
	install -m 644 -D -t $(PREFIX)$(MANDIR)/man5 $(MANPAGE)
	[ "$(COMPRESS)" == "" ] || $(COMPRESS) -f $(PREFIX)$(MANDIR)/man5/$(MANPAGE)

clean:
	rm -f test $(BACKEND) tags

test:	$(BACKEND) test.c
	$(CC) -o test test.c $(BACKEND) -Wl,-rpath . ${airscan_CFLAGS}
