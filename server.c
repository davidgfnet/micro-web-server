
#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <pwd.h>

#include "server_config.h"
#include "server.h"

#define STATUS_REQ         0               
#define STATUS_RESP        1

const unsigned char crlf_crlf[5] = {0xD,0xA,0xD,0xA,0x0};
const unsigned char * crlf = &crlf_crlf[2];

const unsigned char ok_200[]  = "HTTP/1.1 200 OK\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";
const unsigned char err_404[] = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
const unsigned char err_401[] = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Auth needed\"\r\n\r\nConnection: close\r\n\r\n";
const unsigned char partial_206[]  = "HTTP/1.1 206 Partial content\r\nContent-Range: bytes %lld-%lld/%lld\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";

// Temporary buffer for main thread usage
char tbuffer[WR_BLOCK_SIZE];

char auth_str[128]; // "Basic dXNlcjpwYXNz";

struct mime_type {
	char extension[6];
	char mime_type[32];
};
struct mime_type mtypes[12] = {	{"",		"application/octet-stream"},  // Default mime type
								{"htm",		"text/html"},
								{"html",	"text/html"},
								{"css",		"text/css"},
								{"gif",		"image/gif"},
								{"png",		"image/png"},
								{"jpg",		"image/jpeg"},
								{"jpeg",	"image/jpeg"},
								{"bmp",		"image/bmp"},
								{"xml",		"text/xml"},
								{"mp3",		"audio/mpeg"},
								{"avi",		"video/x-msvideo"}
							};

struct process_task {
	int fd;
	FILE* fdfile;
	long start_time;
	char status, end;
	int offset;
	long long fend;
	unsigned short request_size;
	unsigned char request_data[REQUEST_MAX_SIZE+1];
};
int listenfd;
struct process_task tasks[MAXCLIENTS];
struct pollfd fdtable[MAXCLIENTS+1];

int setNonblocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

char * mime_lookup(char * file) {
	char * extension = &file[strlen(file)-1];
	while (*extension != '.') {
		if (((size_t)extension) < ((size_t)file))
			return mtypes[0].mime_type;  // No extension, default type
		extension--;
	}
	extension++;

	int i;
	for (i = 1; i < sizeof(mtypes)/sizeof(struct mime_type); i++) {
		if (strcasecmp(extension,mtypes[i].extension) == 0) {
			return mtypes[i].mime_type;
		}
	}
	return mtypes[0].mime_type;  // Not found, defaulting
}

long long lof(FILE * fd) {
	long long pos = ftello(fd);
	fseeko(fd,0,SEEK_END);
	long long len = ftello(fd);
	fseeko(fd,pos,SEEK_SET);
	return len;
}


void process_exit(int signal) {
	// Close all the connections and files
	// and then exit

	close(listenfd);

	int i;
	for (i = 0; i < MAXCLIENTS; i++) {
		if (tasks[i].fd != -1) close(tasks[i].fd);
		if (tasks[i].fdfile != 0) fclose(tasks[i].fdfile);
	}

	printf("Terminated by signal %d\n",signal);
	exit(0);
}

int fdtable_lookup(int fd) {
	int k;
	for (k = 0; k < MAXCLIENTS; k++)
		if (fdtable[k].fd == fd)
			return k;

	return 0;
}


void server_run (int port, int ctimeout, char * base_path) {
	signal (SIGTERM, process_exit);
	signal (SIGHUP, process_exit);
	signal (SIGINT, process_exit);
	signal (SIGPIPE, SIG_IGN);

	int num_active_clients = 0;
	int i,j,k;

	/* Force the network socket into nonblocking mode */
	if (setNonblocking(listenfd) < 0) {
		printf("Error  while trying to go NON-BLOCKING\n"); exit(1);
	}

	if(listen(listenfd,5) < 0) {
		printf("Error listening on the port\n"); perror("listen"); exit(1);
	}

	for (i = 0; i < MAXCLIENTS+1; i++) {
		fdtable[i].fd = -1;
		fdtable[i].events = POLLIN;  // By default
		fdtable[i].revents = 0;
	}
	for (i = 0; i < MAXCLIENTS; i++) tasks[i].fd = -1;
	fdtable[0].fd = listenfd;

	while(1) {
		// Unblock if more than 1 second have elapsed (to allow killing dead connections)
		poll(fdtable, num_active_clients+1, 1000);

		if (num_active_clients < MAXCLIENTS) {
			int fd = accept(listenfd, NULL, NULL);
			if (fd != -1) {
				setNonblocking(fd);
				// Add the fd to the poll wait table!
				int i = ++num_active_clients;
				fdtable[i].fd = fd;
				fdtable[i].events = POLLIN;  // By default we read (the request)
				for (j = 0; j < MAXCLIENTS; j++)
					if (tasks[j].fd < 0) break;

				tasks[j].fd = fd;
				tasks[j].request_size = 0;
				tasks[j].status = STATUS_REQ;
				tasks[j].fdfile = 0;
				tasks[j].end = 0;
				time(&tasks[j].start_time);
			}
		}

		// Process the data
		for (i = 0; i < MAXCLIENTS; i++) {
			if (tasks[i].fd >= 0) {
				int force_end = 0;

				// HTTP REQUEST READ
				if (tasks[i].status == STATUS_REQ) {
					// Keep reading the request message
					int readbytes = read(tasks[i].fd,&tasks[i].request_data[tasks[i].request_size],REQUEST_MAX_SIZE-tasks[i].request_size);
					if (readbytes >= 0) {
						tasks[i].request_size += readbytes;

						if (readbytes > 0)
							time(&tasks[i].start_time);   // Update timeout

						// Put null ends
						tasks[i].request_data[tasks[i].request_size] = 0;
						// Check request end, ignore the body!
						if (strstr(tasks[i].request_data,crlf_crlf) != 0) {
							// We got all the header, reponse now!
							tasks[i].status = STATUS_RESP;
							fdtable[fdtable_lookup(tasks[i].fd)].events = POLLOUT;
							// Parse the request header
							
							int userange = 1;
							long long fstart = 0;
							if (header_attr_lookup(tasks[i].request_data,"Range:",crlf) < 0) {
								userange = 0;
								tasks[i].fend = LLONG_MAX;
							}else{
								if (parse_range_req(param_str,&fstart,&tasks[i].fend) < 0) {
									userange = 0;
									fstart = 0;
									tasks[i].fend = LLONG_MAX;
								}
							}

							// Auth
							int auth_ok = 1;
							if (auth_str[0] != 0) {
								if (header_attr_lookup(tasks[i].request_data,"Authorization:",crlf) >= 0) {
									if (strcmp(param_str, auth_str) != 0)
										auth_ok = 0;
								}
								else auth_ok = 0;
							}
							
							if (auth_ok) {
								header_attr_lookup(tasks[i].request_data,"GET "," "); // Get the file
								char file_path[MAX_PATH_LEN*2];
								path_create(base_path,param_str,file_path);

								FILE * fd = fopen(file_path,"rb");
								if (fd == NULL) {
									// Not found! 404 here
									strcpy(tasks[i].request_data,err_404);
									tasks[i].request_size = strlen(err_404);
								}else{
									long long len = lof(fd);
									char * mimetype = mime_lookup(file_path);
									if (tasks[i].fend > len-1) tasks[i].fend = len-1;  // Last byte, not size
									long long content_length = tasks[i].fend - fstart + 1;

									if (userange) {
										sprintf(tasks[i].request_data,partial_206,fstart,tasks[i].fend,len,content_length,mimetype);
										tasks[i].request_size = strlen(tasks[i].request_data);
									}else{
										sprintf(tasks[i].request_data,ok_200,content_length,mimetype);
										tasks[i].request_size = strlen(tasks[i].request_data);
									}
									tasks[i].fdfile = fd;
									fseeko(fd,fstart,SEEK_SET); // Seek the first byte
								}
							}
							else {
								strcpy(tasks[i].request_data,err_401);
								tasks[i].request_size = strlen(err_401);
							}
							tasks[i].offset = 0;
						}
					}
					else if (errno != EAGAIN && errno != EWOULDBLOCK)
						force_end = 1;  // Some error, just close
				}
				
				// HTTP RESPONSE BODY WRITE
				if (tasks[i].status == STATUS_RESP && force_end == 0) {
					if (tasks[i].offset < tasks[i].request_size) {  // Header
						int bwritten = write(tasks[i].fd,&tasks[i].request_data[tasks[i].offset],tasks[i].request_size-tasks[i].offset);

						if (bwritten >= 0) {
							tasks[i].offset += bwritten;
							time(&tasks[i].start_time);   // Update timeout
						}
						else if (errno != EAGAIN && errno != EWOULDBLOCK)
							force_end = 1;  // Some unknown error!
					}else{ // Body
						// Fetch some data from the file
						if (tasks[i].fdfile == 0) {  // No file!
							force_end = 1;
						}else{
							int toread = WR_BLOCK_SIZE;
							if (toread > (tasks[i].fend + 1 - ftello(tasks[i].fdfile))) toread = (tasks[i].fend + 1 - ftello(tasks[i].fdfile));
							if (toread < 0) toread = 0; // File could change its size...

							int numb = fread(tbuffer,1,toread,tasks[i].fdfile);
							if (numb == 0 || toread == 0) {
								// End of file, close the connection
								force_end = 1;
							}
							else if (numb > 0) {
								// Try to write the data to the socket
								int bwritten = write(tasks[i].fd,tbuffer,numb);

								// Seek back if necessary
								int bw = bwritten >= 0 ? bwritten : 0;
								fseek(tasks[i].fdfile,-numb+bw,SEEK_CUR);

								if (bwritten >= 0) {
									time(&tasks[i].start_time);   // Update timeout
								}
								else if (errno != EAGAIN && errno != EWOULDBLOCK)
									force_end = 1;  // Some unknown error!
							}
							else
								force_end = 1;
						}
					}
				}

				// TIMEOUT CLOSE CONNECTION!
				long cur_time; time(&cur_time);
				if (cur_time-tasks[i].start_time > ctimeout)
					force_end = 1;

				// CONNECTION CLOSE
				if (force_end == 1) {
					if (tasks[i].fdfile != 0)
						fclose(tasks[i].fdfile);

					tasks[i].end = 1;   // Mark close
				}

				if (tasks[i].end) {  // Try to close the socket
					// close connection and update the fdtable
					if (close(tasks[i].fd) == 0) {
						for (k = 0; k < MAXCLIENTS; k++)
							if (fdtable[k].fd == tasks[i].fd) {
								for (j = k; j < MAXCLIENTS; j++)
									fdtable[j].fd = fdtable[j+1].fd;
								fdtable[MAXCLIENTS].fd = -1;
								break;
							}
						tasks[i].fd = -1;
						tasks[i].fdfile = 0;
						tasks[i].end = 0;
						num_active_clients--;
					}
				}
			}
		}
	}
}

int main (int argc, char ** argv) {
	int port = 80;
	int timeout = 8;
	unsigned char base_path[MAX_PATH_LEN] = {0};
	getcwd(base_path,MAX_PATH_LEN-1);
	char sw_user [256];
	strcpy(sw_user,"nobody");

	int i;
	for (i = 1; i < argc; i++) {
		// Port
		if (strcmp(argv[i],"-p") == 0) {
			sscanf(argv[i+1],"%d",&port);
		}
		// Timeout
		if (strcmp(argv[i],"-t") == 0) {
			sscanf(argv[i+1],"%d",&timeout);
		}
		// Base dir
		if (strcmp(argv[i],"-d") == 0) {
			strcpy(base_path,argv[i+1]);
		}
		// User drop
		if (strcmp(argv[i],"-u") == 0) {
			strcpy(sw_user, argv[i+1]);
		}
		// Auth
		if (strcmp(argv[i],"-a") == 0) {
			strcpy(auth_str, argv[i+1]);
		}
		// Help
		if (strcmp(argv[i],"-h") == 0) {
			printf("Usage: server [-p port] [-t timeout] [-d base_dir] [-u user]\n"
			"    -p     Port             (Default port is 80)\n"
			"    -t     Timeout          (Default timeout is 8 seconds of network inactivity)\n"
			"    -d     Base Dir         (Default dir is working dir)\n"
			"    -u     Switch to user   (Switch to specified user (may drop privileges, by default nobody))\n"
			"    -a     HTTP Auth        (Specify an auth string, i.e. \"Basic dXNlcjpwYXNz\")\n"
			);
			exit(0);
		}
	}
	
	// Bind port!
	struct sockaddr_in servaddr;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port   = htons(port);
	int yes = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	if (bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
		printf("Error binding the port.\n",errno); perror("bind"); exit(1);
	}

	// Switch to user
	struct passwd * pw = getpwnam(sw_user);
	if (pw == 0) {
		fprintf(stderr,"Could not find user %s\n",sw_user);
		exit(1);
	}
	setgid(pw->pw_gid);
	setuid(pw->pw_uid);
	
	server_run(port, timeout, base_path);
}


