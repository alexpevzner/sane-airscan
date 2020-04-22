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
PKG_CONFIG = /usr/bin/pkg-config

# These variables are not intended to be user-settable
OBJDIR  = objs/
CONFDIR = /etc/sane.d
LIBDIR := $(shell $(PKG_CONFIG) --variable=libdir sane-backends)
BACKEND = libsane-airscan.so.1
MANPAGE = sane-airscan.5
DEPENDS	:= avahi-client avahi-glib libjpeg libsoup-2.4 libxml-2.0 libtiff-4
DEPENDS += libpng

# Sources and object files
SRC	= $(wildcard airscan*.c) sane_strstatus.c
OBJ	= $(addprefix $(OBJDIR), $(SRC:.c=.o))

# Obtain CFLAGS and LDFLAGS for dependencies
airscan_CFLAGS	= $(CFLAGS)
airscan_CFLAGS += -fPIC
airscan_CFLAGS += $(foreach lib, $(DEPENDS), $(shell pkg-config --cflags $(lib)))

airscan_LIBS := $(foreach lib, $(DEPENDS), $(shell pkg-config --libs $(lib))) -lm

airscan_LDFLAGS = $(LDFLAGS)
airscan_LDFLAGS += $(airscan_LIBS)
airscan_LDFLAGS += -Wl,--version-script=airscan.sym

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
airscan_LDFLAGS += -Wl,-z,nodelete

$(OBJDIR)%.o: %.c Makefile airscan.h
	mkdir -p $(OBJDIR)
	$(CC) -c -o $@ $< $(CPPFLAGS) $(airscan_CFLAGS)

.PHONY: all clean install

all:	tags $(BACKEND) test test-decode

tags: $(SRC) airscan.h test.c test-decode.c
	-ctags -R .

$(BACKEND): $(OBJ) Makefile airscan.sym
	$(CC) -o $(BACKEND) -shared $(OBJ) $(airscan_LDFLAGS)

install: all
	mkdir -p $(DESTDIR)$(PREFIX)$(CONFDIR)
	mkdir -p $(DESTDIR)$(PREFIX)$(CONFDIR)/dll.d
	cp -n airscan.conf $(DESTDIR)$(PREFIX)$(CONFDIR)
	cp -n dll.conf $(DESTDIR)$(PREFIX)$(CONFDIR)/dll.d/airscan
	install -s -D -t $(DESTDIR)$(PREFIX)$(LIBDIR)/sane $(BACKEND)
	mkdir -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man5
	install -m 644 -D -t $(DESTDIR)$(PREFIX)$(MANDIR)/man5 $(MANPAGE)
	[ "$(COMPRESS)" = "" ] || $(COMPRESS) -f $(DESTDIR)$(PREFIX)$(MANDIR)/man5/$(MANPAGE)

clean:
	rm -f test $(BACKEND) tags
	rm -rf $(OBJDIR)

test:	$(BACKEND) test.c
	$(CC) -o test test.c $(BACKEND) -Wl,-rpath . ${airscan_CFLAGS}

test-decode: test-decode.c $(OBJ)
	 $(CC) -o test-decode test-decode.c $(OBJ) $(CPPFLAGS) $(airscan_CFLAGS) $(airscan_LIBS)
