all:	libsane-airscan.so

libsane-airscan.so: airscan.c
	ctags -R .
	gcc -o libsane-airscan.so -shared -O2 -W -Wall airscan.c
