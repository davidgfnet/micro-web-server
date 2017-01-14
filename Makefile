
all:
	gcc -O2 -ggdb -o server server.c -Wall
	strip -s server

clean:
	rm -f server regression

.PHONY:	regression
regression:
	gcc -O0 -o regression tests/regression.c -I . -ggdb

