CFLAGS	= -O2 -g -W -Wall -fPIC
CFLAGS += `pkg-config --cflags --libs avahi-client`
CFLAGS += `pkg-config --cflags --libs avahi-glib`
CFLAGS += `pkg-config --cflags --libs libjpeg`
CFLAGS += `pkg-config --cflags --libs libsoup-2.4`

all:	libsane-airscan.so test

libsane-airscan.so: Makefile airscan.c
	@ctags -R .
	gcc -o libsane-airscan.so -shared ${CFLAGS} airscan.c

test:	libsane-airscan.so test.c
	gcc -o test test.c libsane-airscan.so -Wl,-rpath .
