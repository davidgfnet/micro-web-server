
all:	mhttpsrv mhttpsrvp

mhttpsrv:
	gcc -std=gnu99 -O2 -ggdb -o mhttpsrv server.c -Wall
	strip -s mhttpsrv

mhttpsrvp:
	gcc -std=gnu99 -O2 -ggdb -o mhttpsrvp server.c tadns.c -DHTTP_PROXY_ENABLED -Wall
	strip -s mhttpsrvp

clean:
	rm -f mhttpsrv mhttpsrvp regression

.PHONY:	regression
regression:
	gcc -O0 -o regression tests/regression.c -I . -ggdb

