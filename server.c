
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

#define MAXCLIENTS       128
#define STATUS_REQ         0
#define STATUS_RESP        1

#ifndef LLONG_MAX
	#define LLONG_MAX 2094967295
#endif

#define REQUEST_MAX_SIZE  2047
#define WR_BLOCK_SIZE	 1024

#define MAX_PATH_LEN	  2048
#define DEFAULT_DOC	"index.htm"

const unsigned char crlf_crlf[5] = {0xD,0xA,0xD,0xA,0x0};
const unsigned char * crlf = &crlf_crlf[2];

const unsigned char ok_200[]  = "HTTP/1.1 200 OK\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";
const unsigned char err_404[] = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
const unsigned char partial_206[]  = "HTTP/1.1 206 Partial content\r\nContent-Range: bytes %lld-%lld/%lld\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";

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

// writes to param_str the value of the parameter in the request trimming whitespaces
char param_str[REQUEST_MAX_SIZE*3];
int header_attr_lookup(const char * request, const char * param, const char * param_end) {
	char * ptr = strstr(request,param);  // ptr to the parameter line
	if (ptr == 0)
		return -1;
	ptr += strlen(param);  // ptr now points to the start of the data
	while (*ptr == ' ') ptr++;  // trim whitespaces

	char * ptr2 = strstr(ptr,param_end);   // ptr to the end of the line
	if (ptr2 == 0)
		return -1;

	int len = (((size_t)ptr2) - ((size_t)ptr));
	if (len < 0) return -1;
	memcpy(param_str, ptr, len);  // Copy the data to the buffer
	param_str[len] = 0;

	return len;  // Returns the size of the parameter
}

int parse_range_req(char * req_val, long long * start, long long * end) {
	// Req_val will be something like:
	// bytes=120-   (download from byte 120 to the end)
	// bytes=-120   (download the last 120 bytes)
	// bytes=120-123 (interval)
	// bytes=1-2,5-6 (multiple chunks)
	// We only support %- or %-%

	// Check if there's a comma!
	if (strstr(req_val,",") != 0)
		return -1;

	// Strip bytes prefix
	char * ptr = strstr(req_val,"=");
	if (ptr == 0) ptr = req_val;
	else ptr++; //Skip "="

	// Whitespace strip
	while (*ptr == ' ') ptr++;

	if (*ptr == 0) return -1; // Empty!!!

	// Read the start
	sscanf(ptr,"%lld %*s",start);
	
	// Search for "-" 
	ptr = strstr(ptr,"-");
	if (ptr == 0) {
		// Assume no end then... use Maximum Signed long long (2^63-1) on all platforms
		*end = LLONG_MAX;
		return 0;
	}
	else
		ptr++;

	// More whitespace
	while (*ptr == ' ') ptr++;

	if (*ptr == 0) {
		// Assume no end then... use Maximum Signed long long (2^63-1) on all platforms
		*end = LLONG_MAX;	
		return 0;	
	}

	// Read the end
	sscanf(ptr,"%lld %*s",end);

	return 0;
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

// strcpy with overlap buffers
void strcpy_o(char * dest, char * src) {
	while (*src != 0) {
		*dest++ = *src++;
	}
	*dest = 0;
}

void path_create(char * base_path, char * req_file, char * out_file) {
	out_file[0] = 0;
	strcpy(out_file,base_path);
	strcat(out_file,"/");
	strcat(out_file,req_file);

	char * pos;
	// Remove ".."
	while ((pos = strstr(out_file,"..")) != 0) {
		strcpy_o(pos,pos+2);
	}
	// Remove "//"
	while ((pos = strstr(out_file,"//")) != 0) {
		strcpy_o(pos,pos+1);
	}

	// If it ends as "/" it's a path, so append default file
	if (out_file[strlen(out_file)-1] == '/')
		strcat(out_file,DEFAULT_DOC);
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
							
							header_attr_lookup(tasks[i].request_data,"GET "," "); // Get the file
							char file_path[MAX_PATH_LEN];
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

								if (userange) {
									sprintf(tasks[i].request_data,partial_206,fstart,tasks[i].fend,len,len,mimetype);
									tasks[i].request_size = strlen(tasks[i].request_data);
								}else{
									sprintf(tasks[i].request_data,ok_200,len,mimetype);
									tasks[i].request_size = strlen(tasks[i].request_data);
								}
								tasks[i].fdfile = fd;
								fseeko(fd,fstart,SEEK_SET); // Seek the first byte
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
							char tbuffer[WR_BLOCK_SIZE];
							int toread = WR_BLOCK_SIZE;
							if (toread > (tasks[i].fend + 1 - ftello(tasks[i].fdfile))) toread = (tasks[i].fend + 1 - ftello(tasks[i].fdfile));

							int numb = fread(tbuffer,1,toread,tasks[i].fdfile);
							if (numb == 0 || toread == 0) {
								// End of file, close the connection
								force_end = 1;
							}
							else if (numb > 0) {
								// Try to write the data to the socket
								int bwritten = write(tasks[i].fd,tbuffer,numb);

								if (bwritten >= 0) {
									fseek(tasks[i].fdfile,-numb+bwritten,SEEK_CUR);
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
		// Help
		if (strcmp(argv[i],"-h") == 0) {
			printf("Usage: server [-p port] [-t timeout] [-d base_dir]\n \
			Default port is 80\n\
			Default timeout is 8 seconds of network inactivity\n\
			Default dir is working dir\n");
			exit(0);
		}
	}

	server_run(port, timeout, base_path);
}


