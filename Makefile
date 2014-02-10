
all:
	gcc -O2 -o server server.c 
	strip -s server

clean:
	rm -f server regression

.PHONY:	regression
regression:
	gcc -O0 -o regression tests/regression.c -I . -ggdb

