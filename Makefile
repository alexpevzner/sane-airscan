# USER-SETTABLE VARIABLES
#
# The following variables can be overridden by user (i.e.,
# make install DESTDIR=/tmp/xxx):
#
#   Name     Default                    Description
#   ----     -------                    -----------
#   DESTDIR                             Destination directory for make install
#   CC         gcc                      C compiler
#   CPPFLAGS                            C preprocessor flags
#   CFLAGS     -O2 -g -W -Wall -Werror  C compiler flags
#   LDFLAGS                             Linker flags
#   COMPRESS   gzip -n                  Program to compress man page, or ""
#   STRIP      -s                       Stripping of debug symbols
#   PKG_CONFIG pkg-config               Program to query dependencies info
#   INSTALL    install                  Installation program
#
# Variables for Installation Directories
#   Name         Linux               BSD
#   ----         -----               ---
#   prefix       /usr                /usr/local
#   exec_prefix  $(prefix)           $(prefix)
#   sysconfdir   /etc                $(prefix)/etc
#   bindir       $(exec_prefix)/bin  $(exec_prefix)/bin
#   libdir       $(shell $(PKG_CONFIG) --variable=libdir sane-backends)
#   datarootdir  $(prefix)/share     $(prefix)/share
#   mandir       $(datarootdir)/man  $(datarootdir)/man
#

CC		= gcc
COMPRESS 	= gzip -n
CFLAGS		+= -O2 -g -W -Wall -Werror -pthread $(CPPFLAGS)
PKG_CONFIG 	= pkg-config
STRIP 		= -s
INSTALL 	= install

ifeq "$(shell uname -s)" "Linux"
    prefix	?= /usr
else
    prefix	?= /usr/local
endif

ifeq "$(prefix)" "/usr"
    sysconfdir	= /etc
else
    sysconfdir	= $(prefix)/etc
endif

exec_prefix	= $(prefix)
bindir          = $(exec_prefix)/bin
libdir		= $(shell $(PKG_CONFIG) --variable=libdir sane-backends)
datarootdir	= $(prefix)/share
mandir		= $(datarootdir)/man

# These variables are not intended to be user-settable
OBJDIR		= objs/
CONFDIR		= $(sysconfdir)/sane.d
BACKEND		= libsane-airscan.so.1
DISCOVER	= airscan-discover
LIBAIRSCAN	= $(OBJDIR)/libairscan.a
MAN_DISCOVER	= $(DISCOVER).1
MAN_DISCOVER_TITLE = "SANE Scanner Access Now Easy"
MAN_BACKEND	= sane-airscan.5
MAN_BACKEND_TITLE = "AirScan (eSCL) and WSD SANE backend"
DEPS_COMMON	:= avahi-client libxml-2.0 gnutls
DEPS_CODECS	:= libjpeg libpng libtiff-4

CFLAGS		+= -D CONFIG_SANE_CONFIG_DIR=\"$(CONFDIR)\"

# Sources and object files
SRC	= $(wildcard airscan-*.c) sane_strstatus.c http_parser.c
OBJ	= $(addprefix $(OBJDIR), $(SRC:.c=.o))

# Obtain CFLAGS and LDFLAGS for dependencies
deps_CFLAGS		:= $(foreach lib, $(DEPS_COMMON), $(shell $(PKG_CONFIG) --cflags $(lib)))
deps_CFLAGS		+= $(foreach lib, $(DEPS_CODECS), $(shell $(PKG_CONFIG) --cflags $(lib)))

deps_LIBS 		:= $(foreach lib, $(DEPS_COMMON), $(shell $(PKG_CONFIG) --libs $(lib))) -lm -lpthread
deps_LIBS_CODECS 	:= $(foreach lib, $(DEPS_CODECS), $(shell $(PKG_CONFIG) --libs $(lib)))

# Compute CFLAGS and LDFLAGS for backend and tools
#
# Note, CFLAGS are common, for simplicity, while LDFLAGS are not, to
# avoid linking unneeded libraries
common_CFLAGS		:= $(CFLAGS) $(deps_CFLAGS)
common_CFLAGS 		+= -fPIC

backend_LDFLAGS 	:= $(LDFLAGS)
backend_LDFLAGS 	+= $(deps_LIBS) $(deps_LIBS_CODECS)
backend_LDFLAGS 	+= -lc

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
	mkdir -p $(DESTDIR)/$(bindir)
	mkdir -p $(DESTDIR)/$(CONFDIR)
	mkdir -p $(DESTDIR)/$(CONFDIR)/dll.d
	$(INSTALL) $(STRIP) $(DISCOVER) $(DESTDIR)/$(bindir)
	[ -e $(DESTDIR)/$(CONFDIR)/airscan.conf ] || cp airscan.conf $(DESTDIR)/$(CONFDIR)
	[ -e $(DESTDIR)/$(CONFDIR)/dll.d/airscan ] || cp dll.conf $(DESTDIR)/$(CONFDIR)/dll.d/airscan
	mkdir -p $(DESTDIR)/$(libdir)/sane
	$(INSTALL) $(STRIP) $(BACKEND) $(DESTDIR)/$(libdir)/sane
	mkdir -p $(DESTDIR)/$(mandir)/man1
	mkdir -p $(DESTDIR)/$(mandir)/man5
	$(INSTALL) -m 644 $(MAN_DISCOVER) $(DESTDIR)/$(mandir)/man1
	$(INSTALL) -m 644 $(MAN_BACKEND) $(DESTDIR)/$(mandir)/man5
	[ "$(COMPRESS)" = "" ] || $(COMPRESS) -f $(DESTDIR)/$(mandir)/man1/$(MAN_DISCOVER)
	[ "$(COMPRESS)" = "" ] || $(COMPRESS) -f $(DESTDIR)/$(mandir)/man5/$(MAN_BACKEND)

clean:
	rm -f test test-decode test-multipart test-zeroconf test-uri $(BACKEND) tags
	rm -rf $(OBJDIR)

uninstall:
	rm -f $(DESTDIR)/$(bindir)/$(DISCOVER)
	rm -f $(DESTDIR)/$(CONFDIR)/dll.d/airscan
	rm -f $(DESTDIR)/$(libdir)/sane/$(BACKEND)
	rm -f $(DESTDIR)/$(mandir)/man1/$(MAN_DISCOVER)*
	rm -f $(DESTDIR)/$(mandir)/man5/$(MAN_BACKEND)*

check: all
	./test-uri
	./test-zeroconf

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
