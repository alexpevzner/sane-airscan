CFLAGS	= -O2 -W -Wall
CFLAGS += `pkg-config --cflags --libs avahi-client`
CFLAGS += `pkg-config --cflags --libs libjpeg`

all:	libsane-airscan.so

libsane-airscan.so: Makefile airscan.c
	ctags -R .
	gcc -o libsane-airscan.so -shared ${CFLAGS} airscan.c
