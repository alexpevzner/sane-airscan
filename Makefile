SRC	= \
	airscan.c \
	airscan-array.c \
	airscan-devcaps.c \
	airscan-xml.c \
	sane_strstatus.c

CFLAGS	= -O2 -g -W -Wall -fPIC
CFLAGS += `pkg-config --cflags --libs avahi-client`
CFLAGS += `pkg-config --cflags --libs avahi-glib`
CFLAGS += `pkg-config --cflags --libs libjpeg`
CFLAGS += `pkg-config --cflags --libs libsoup-2.4`
CFLAGS += `pkg-config --cflags --libs libxml-2.0`
CFLAGS += -Wl,--version-script=airscan.sym

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

all:	libsane-airscan.so test

libsane-airscan.so: Makefile $(SRC) airscan.h airscan.sym
	@ctags -R .
	gcc -o libsane-airscan.so -shared ${CFLAGS} $(SRC)

test:	libsane-airscan.so test.c
	#gcc -o test test.c -l sane
	gcc -o test test.c libsane-airscan.so -Wl,-rpath .
