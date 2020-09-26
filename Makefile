# USER-SETTABLE VARIABLES
#
# The following variables can be overridden by user (i.e.,
# make install DESTDIR=/tmp/xxx):
#
#   Name     Default                    Description
#   ----     -------                    -----------
#   DESTDIR                             Destination directory for make install
#   PREFIX           	                Non-standard: appended to DESTDIR
#   CC         gcc                      C compiler
#   CPPFLAGS                            C preprocessor flags
#   CFLAGS     -O2 -g -W -Wall -Werror  C compiler flags
#   LDFLAGS                             Linker flags
#   COMPRESS   gzip                     Program to compress man page, or ""
#   MANDIR     /usr/share/man/          Where to install man page
#   STRIP      -s                       Stripping of debug symbols
#   PKG_CONFIG pkg-config               Program to query dependencies info
#   INSTALL    install                  Installation program

CC	= gcc
COMPRESS = gzip
CFLAGS	+= -O2 -g -W -Wall -Werror -pthread $(CPPFLAGS)
MANDIR	= /usr/share/man/
PKG_CONFIG = /usr/bin/pkg-config
STRIP 	= -s
INSTALL = install

# These variables are not intended to be user-settable
OBJDIR  = objs/
BINDIR 	= /usr/bin
CONFDIR = /etc/sane.d
LIBDIR 	:= $(shell $(PKG_CONFIG) --variable=libdir sane-backends)
BACKEND = libsane-airscan.so.1
DISCOVER = airscan-discover
LIBAIRSCAN = $(OBJDIR)/libairscan.a
MAN_DISCOVER = $(DISCOVER).1
MAN_DISCOVER_TITLE = "SANE Scanner Access Now Easy"
MAN_BACKEND = sane-airscan.5
MAN_BACKEND_TITLE = "AirScan (eSCL) and WSD SANE backend"
DEPS_COMMON := avahi-client libxml-2.0 gnutls
DEPS_CODECS := libjpeg libpng

# Sources and object files
SRC	= $(wildcard airscan-*.c) sane_strstatus.c http_parser.c
OBJ	= $(addprefix $(OBJDIR), $(SRC:.c=.o))

# Obtain CFLAGS and LDFLAGS for dependencies
deps_CFLAGS		:= $(foreach lib, $(DEPS_COMMON), $(shell $(PKG_CONFIG) --cflags $(lib)))
deps_CFLAGS		+= $(foreach lib, $(DEPS_CODECS), $(shell $(PKG_CONFIG) --cflags $(lib)))

deps_LIBS 		:= $(foreach lib, $(DEPS_COMMON), $(shell $(PKG_CONFIG) --libs $(lib))) -lm
deps_LIBS_CODECS 	:= $(foreach lib, $(DEPS_CODECS), $(shell $(PKG_CONFIG) --libs $(lib)))

# Compute CFLAGS and LDFLAGS for backend and tools
#
# Note, CFLAGS are common, for simplicity, while LDFLAGS are not, to
# avoid linking unneeded libraries
common_CFLAGS		:= $(CFLAGS) $(deps_CFLAGS)
common_CFLAGS 		+= -fPIC

backend_LDFLAGS 	:= $(LDFLAGS)
backend_LDFLAGS 	+= $(deps_LIBS) $(deps_LIBS_CODECS)
backend_LDFLAGS 	+= -Wl,--version-script=airscan.sym

tools_LDFLAGS 		:= $(LDFLAGS)
tools_LDFLAGS 		+= $(deps_LIBS)
tools_LDFLAGS 		+= -fPIE

tests_LDFLAGS		:= $(tools_LDFLAGS) $(deps_LIBS_CODECS)

$(OBJDIR)%.o: %.c Makefile airscan.h
	mkdir -p $(OBJDIR)
	$(CC) -c -o $@ $< $(CPPFLAGS) $(common_CFLAGS)

.PHONY: all clean install man

all:	tags $(BACKEND) $(DISCOVER) test test-decode test-multipart test-zeroconf test-uri

tags: $(SRC) airscan.h test.c test-decode.c test-multipart.c test-zeroconf.c test-uri.c
	-ctags -R .

$(BACKEND): $(OBJDIR)airscan.o $(LIBAIRSCAN) airscan.sym
	$(CC) -o $(BACKEND) -shared $(OBJDIR)/airscan.o $(LIBAIRSCAN) $(backend_LDFLAGS)

$(DISCOVER): $(OBJDIR)discover.o $(LIBAIRSCAN)
	 $(CC) -o $(DISCOVER) discover.c $(CPPFLAGS) $(common_CFLAGS) $(LIBAIRSCAN) $(tools_LDFLAGS)

$(LIBAIRSCAN): $(OBJ) Makefile
	ar cru $(LIBAIRSCAN) $(OBJ)

install: all
	mkdir -p $(DESTDIR)$(PREFIX)$(BINDIR)
	mkdir -p $(DESTDIR)$(PREFIX)$(CONFDIR)
	mkdir -p $(DESTDIR)$(PREFIX)$(CONFDIR)/dll.d
	$(INSTALL) $(STRIP) -D -t $(DESTDIR)$(PREFIX)$(BINDIR) $(DISCOVER)
	cp -n airscan.conf $(DESTDIR)$(PREFIX)$(CONFDIR)
	cp -n dll.conf $(DESTDIR)$(PREFIX)$(CONFDIR)/dll.d/airscan
	$(INSTALL) $(STRIP) -D -t $(DESTDIR)$(PREFIX)$(LIBDIR)/sane $(BACKEND)
	mkdir -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man5
	$(INSTALL) -m 644 -D -t $(DESTDIR)$(PREFIX)$(MANDIR)/man1 $(MAN_DISCOVER)
	$(INSTALL) -m 644 -D -t $(DESTDIR)$(PREFIX)$(MANDIR)/man5 $(MAN_BACKEND)
	[ "$(COMPRESS)" = "" ] || $(COMPRESS) -f $(DESTDIR)$(PREFIX)$(MANDIR)/man1/$(MAN_DISCOVER)
	[ "$(COMPRESS)" = "" ] || $(COMPRESS) -f $(DESTDIR)$(PREFIX)$(MANDIR)/man5/$(MAN_BACKEND)

clean:
	rm -f test test-decode test-multipart test-zeroconf test-uri $(BACKEND) tags
	rm -rf $(OBJDIR)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)$(BINDIR)/$(DISCOVER)
	rm -f $(DESTDIR)$(PREFIX)$(CONFDIR)/dll.d/airscan
	rm -f $(DESTDIR)$(PREFIX)$(LIBDIR)/sane/$(BACKEND)
	rm -f $(DESTDIR)$(PREFIX)$(MANDIR)/man1/$(MAN_DISCOVER)*
	rm -f $(DESTDIR)$(PREFIX)$(MANDIR)/man5/$(MAN_BACKEND)*

man: $(MAN_DISCOVER) $(MAN_BACKEND)

$(MAN_DISCOVER): $(MAN_DISCOVER).md
	ronn --roff --manual=$(MAN_DISCOVER_TITLE) $(MAN_DISCOVER).md

$(MAN_BACKEND): $(MAN_BACKEND).md
	ronn --roff --manual=$(MAN_BACKEND_TITLE) $(MAN_BACKEND).md

test:	$(BACKEND) test.c
	$(CC) -o test test.c $(BACKEND) -Wl,-rpath . $(LDFLAGS) ${common_CFLAGS}

test-decode: test-decode.c $(LIBAIRSCAN)
	 $(CC) -o test-decode test-decode.c $(CPPFLAGS) $(common_CFLAGS) $(LIBAIRSCAN) $(tests_LDFLAGS)

test-multipart: test-multipart.c $(LIBAIRSCAN)
	 $(CC) -o test-multipart test-multipart.c $(CPPFLAGS) $(common_CFLAGS) $(LIBAIRSCAN) $(tests_LDFLAGS)

test-zeroconf: test-zeroconf.c $(LIBAIRSCAN)
	 $(CC) -o test-zeroconf test-zeroconf.c $(CPPFLAGS) $(common_CFLAGS) $(LIBAIRSCAN) $(tests_LDFLAGS)

test-uri: test-uri.c $(LIBAIRSCAN)
	 $(CC) -o test-uri test-uri.c $(CPPFLAGS) $(common_CFLAGS) $(LIBAIRSCAN) $(tests_LDFLAGS)
