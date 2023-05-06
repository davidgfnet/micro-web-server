
all:	mhttpsrv mhttpsrvp

mhttpsrv:
	gcc -std=gnu99 -O2 -ggdb -o mhttpsrv server.c -Wall -lzip
	strip -s mhttpsrv

clean:
	rm -f mhttpsrv regression

.PHONY:	regression
regression:
	gcc -O0 -o regression tests/regression.c -I . -ggdb

