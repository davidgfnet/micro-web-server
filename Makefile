
all:
	gcc -O2 -o server server.c 
	strip -s server

clean:
	rm -f server

