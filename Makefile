
all:	mhttpsrv mhttpsrvp

mhttpsrv:
	gcc -O2 -ggdb -o mhttpsrv server.c -Wall
	strip -s mhttpsrv

mhttpsrvp:
	gcc -O2 -ggdb -o mhttpsrvp server.c tadns.c -DHTTP_PROXY_ENABLED -Wall
	strip -s mhttpsrvp

clean:
	rm -f mhttpsrv mhttpsrvp regression

.PHONY:	regression
regression:
	gcc -O0 -o regression tests/regression.c -I . -ggdb

