micro-web-server
================

Small HTTP server for serving static websites and files

The aim of the project is to create a really small web server 
which uses very little memory and just one thread to serve
files on the net. I've been using it on routers and small 
computers (like NAS).

Instructions
------------

Just do a "make" on any POSIX compatible system and the server
executable will be generated

To view the run options run it with the "-h" option. Typically
the server is executed using the -p option to specify the listen
port and the -d option to specify the base directory to serve.
It does not support virtual hosting.

