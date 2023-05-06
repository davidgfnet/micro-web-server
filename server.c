
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <pwd.h>
#include <assert.h>
#include <zip.h>

#include "server_config.h"
#include "server.h"

#define STATUS_REQ         0               
#define STATUS_RESP        1

const char ok_200[]  = "HTTP/1.1 200 OK\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";
const char err_401[] = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Auth needed\"\r\n\r\nConnection: close\r\n\r\n";
const char err_403[] = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
const char err_404[] = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
const char err_405[] = "HTTP/1.1 405 Method not allowed\r\nConnection: close\r\n\r\n";
const char err_413[] = "HTTP/1.1 413 Request Entity Too Large\r\nConnection: close\r\n\r\n";

char auth_str[128];           // eg. "Basic dXNlcjpwYXNz";

struct process_task {
	int fd;
	zip_file_t* fdfile;
	long start_time;
	char status;
	int offset;
	unsigned short request_size;
	unsigned char request_data[REQUEST_MAX_SIZE+1];
	int tbufbytes;
	char tbuffer[WR_BLOCK_SIZE];  // Temporary buffer for main thread usage

	// List of free/nonfree tasks
	struct process_task * next;
};
int listenfd, epollfd;
struct process_task tasks[MAXCLIENTS];
struct process_task * free_task = &tasks[0];

#define EXIT_ERROR(msg, ecode) \
	{ \
		fprintf(stderr, msg); \
		exit(ecode); \
	}

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

const char * mime_lookup(char * file) {
	char * extension = &file[strlen(file)-1];
	while (*extension != '.') {
		if (((uintptr_t)extension) < ((uintptr_t)file))
			return mtypes[0].mime_type;  // No extension, default type
		extension--;
	}
	// Skip dot
	extension++;

	for (unsigned i = 1; i < sizeof(mtypes)/sizeof(struct mime_type); i++) {
		if (strcasecmp(extension,mtypes[i].extension) == 0) {
			return mtypes[i].mime_type;
		}
	}
	return mtypes[0].mime_type;  // Not found, defaulting
}

void cleanup_task(struct process_task * t) {
	epoll_ctl(epollfd, EPOLL_CTL_DEL, t->fd, NULL);

	if (t->fdfile) {
		zip_fclose(t->fdfile);
		t->fdfile = 0;
	}
	if (t->fd >= 0) {
		close(t->fd);
		t->fd = -1;
	}
}

void process_exit(int signal) {
	// Close all the connections and files
	// and then exit
	struct process_task * t = free_task;
	while (t) {
		cleanup_task(t);
		t = t->next;
	}

	close(listenfd);
	close(epollfd);

	printf("Terminated by signal %d\n",signal);
	exit(0);
}

void epollupdate(int fd, uint32_t events, struct process_task * t) {
	struct epoll_event event;
	event.events = events;
	event.data.ptr = t;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event); 
	epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event); 
}

int check_auth(struct process_task *t) {
	// Auth
	if (auth_str[0] != 0) {
		if (header_attr_lookup((char*)t->request_data, "Authorization:", "\r\n") >= 0) {
			if (strcmp(param_str, auth_str) != 0)
				return 0;
		}
		return 0;
	}
	return 1;
}

int work_request(struct process_task * t, zip_t * zipf) {
	// We don't support long requests due to small buffers
	if (t->request_size >= REQUEST_MAX_SIZE) {
		t->status = STATUS_RESP;
		epollupdate(t->fd, POLLOUT, t);
		RETURN_STRBUF(t, err_413)
	}			

	int readbytes = read(t->fd, &t->request_data[t->request_size], REQUEST_MAX_SIZE - t->request_size);
	if (readbytes >= 0) {
		t->request_size += readbytes;
		if (readbytes > 0) time(&t->start_time);

		// Put null ends
		t->request_data[t->request_size] = 0;
		// Check request end, ignore the body!
		if (strstr((char*)t->request_data, "\r\n\r\n") != 0) {
			// We got all the header, reponse now!
			t->status = STATUS_RESP;
			epollupdate(t->fd, POLLOUT, t);

			if (!check_auth(t))
				RETURN_STRBUF(t, err_401);

			int ishead = 0;
			int isget = header_attr_lookup((char*)t->request_data, "GET ", " ") >= 0; // Get the file
			if (!isget)
				ishead = header_attr_lookup((char*)t->request_data, "HEAD ", " ") >= 0; // Get the file

			char file_path[MAX_PATH_LEN*2];
			path_create(param_str, file_path);

			struct zip_stat zst;
			int code = RTYPE_404;
			if (zip_stat(zipf, file_path, ZIP_FL_ENC_UTF_8, &zst) >= 0)
				code = RTYPE_FIL;

			if (!isget && !ishead) code = RTYPE_405;

			switch (code) {
			case RTYPE_403: RETURN_STRBUF(t, err_403);
			case RTYPE_404: RETURN_STRBUF(t, err_404);
			case RTYPE_405: RETURN_STRBUF(t, err_405);
			case RTYPE_FIL:{// File
				zip_file_t *fd = zip_fopen(zipf, file_path, 0);
				const char * mimetype = mime_lookup(file_path);
				long long content_length = zst.size;

				sprintf((char*)t->request_data, ok_200, content_length, mimetype);
				t->request_size = strlen((char*)t->request_data);

				if (ishead) {
					zip_fclose(fd);
				} else {
					t->fdfile = fd;
				}
				}break;

			};
		}
	}
	else if (errno != EAGAIN && errno != EWOULDBLOCK)
		return 1;  // Some error, just close

	return 0;
}

int work_response(struct process_task * t) {
	if (t->offset == t->request_size) { // Try to feed more data into the buffers
		// Fetch some data from the file
		if (t->fdfile) {
			int toread = WR_BLOCK_SIZE - t->tbufbytes;
			if (toread) {
				int numb = zip_fread(t->fdfile, &t->tbuffer[t->tbufbytes], toread);
				if (numb < 0)
					return 1;
				t->tbufbytes += numb;
			}

			if (t->tbufbytes > 0) {
				// Try to write the data to the socket
				int bwritten = write(t->fd, t->tbuffer, t->tbufbytes);

				if (bwritten >= 0) {
					time(&t->start_time);   // Update timeout
					// Remove bytes from buffer
					memmove(&t->tbuffer[0], &t->tbuffer[bwritten], t->tbufbytes - bwritten);
					t->tbufbytes -= bwritten;
				}
				else if (errno != EAGAIN && errno != EWOULDBLOCK)
					return 1;  // Some unknown error!
			}
			else  // End of file
				return 1;
		}
		else
			return 1;
	}

	if (t->offset < t->request_size) {  // Header
		int bwritten = write(t->fd,&t->request_data[t->offset],t->request_size-t->offset);

		if (bwritten >= 0) {
			t->offset += bwritten;
			time(&t->start_time);   // Update timeout
		}
		else if (errno != EAGAIN && errno != EWOULDBLOCK)
			return 1;  // Some unknown error!
	}
	return 0;
}

void server_run (int port, int ctimeout, zip_t * zipf) {
	signal (SIGTERM, process_exit);
	signal (SIGHUP, process_exit);
	signal (SIGINT, process_exit);
	signal (SIGPIPE, SIG_IGN);

	/* Force the network socket into nonblocking mode */
	if (setNonblocking(listenfd) < 0)
		EXIT_ERROR("Error  while trying to go NON-BLOCKING\n", 1);

	if (listen(listenfd, 5) < 0) {
		perror("listen");
		EXIT_ERROR("Error listening on the port\n", 1);
	}

	for (int i = 0; i < MAXCLIENTS; i++)
		tasks[i].next = &tasks[i+1];
	tasks[MAXCLIENTS-1].next = NULL;

	epollfd = epoll_create(1);

	epollupdate(listenfd, POLLIN, NULL);

	while (1) {
		// Unblock if more than 1 second have elapsed (to allow killing dead connections)
		struct epoll_event revents[MAXCLIENTS];
		int nev = epoll_wait(epollfd, revents, MAXCLIENTS, 1000);

		// Accept loop
		while (1) {
			int fd = accept(listenfd, NULL, NULL);
			if (fd < 0)
				break;

			setNonblocking(fd);

			if (free_task != 0) {
				struct process_task * t = free_task;

				epollupdate(fd, POLLIN, t);
				t->fd = fd;
				t->request_size = 0;
				t->status = STATUS_REQ;
				t->fdfile = 0;
				t->offset = 0;
				t->tbufbytes = 0;
				time(&t->start_time);

				// Remove from free list, add to proc list
				free_task = free_task->next;
			} else
				close(fd);
		}

		// Process the event queue
		for (int e = 0; e < nev; e++) {
			struct process_task * t = (struct process_task *)revents[e].data.ptr;
			if (t == NULL) continue;

			int force_end = 0;

			// HTTP REQUEST READ
			if (t->status == STATUS_REQ)
				force_end |= work_request(t, zipf);

			// HTTP RESPONSE BODY WRITE
			if (t->status == STATUS_RESP && !force_end)
				force_end |= work_response(t);

			// Close on error o timeout
			if (time(0) - t->start_time > ctimeout || force_end) {
				cleanup_task(t);
				t->next = free_task;
				free_task = t;
			}
		}
	}
}

int main (int argc, char ** argv) {
	int port = 8080, timeout = 8;
	char zip_path[MAX_PATH_LEN] = {0};
	char sw_user[256] = "nobody";

	int i;
	for (i = 1; i < argc; i++) {
		// Port
		if (strcmp(argv[i],"-p") == 0)
			sscanf(argv[++i], "%d", &port);
		// Timeout
		if (strcmp(argv[i],"-t") == 0)
			sscanf(argv[++i], "%d", &timeout);
		// Zip file to serve
		if (strcmp(argv[i],"-z") == 0)
			strcpy(zip_path, argv[++i]);
		// User drop
		if (strcmp(argv[i],"-u") == 0)
			strcpy(sw_user, argv[++i]);
		// Auth
		if (strcmp(argv[i],"-a") == 0)
			strcpy(auth_str, argv[++i]);
		// Help
		if (strcmp(argv[i],"-h") == 0) {
			printf("Usage: server [-p port] [-t timeout] [-z zip_file] [-u user]\n"
			"    -p     Port             (Default port is 8080)\n"
			"    -t     Timeout          (Default timeout is 8 seconds of network inactivity)\n"
			"    -z     Zip file         (Zip file to serve)\n"
			"    -u     Switch to user   (Switch to specified user (may drop privileges, by default nobody))\n"
			"    -a     HTTP Auth        (Specify an auth string, i.e. \"Basic dXNlcjpwYXNz\")\n"
			);
			exit(0);
		}
	}

	// Open zip file
	zip_t * zipf = zip_open(zip_path, ZIP_RDONLY, NULL);
	if (!zipf) {
		fprintf(stderr,"Could not open zip file '%s'\n", zip_path);
		exit(1);
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
		printf("Error %u binding the port.\n", errno); perror("bind"); exit(1);
	}

	// Switch to user
	struct passwd * pw = getpwnam(sw_user);
	if (pw == 0) {
		fprintf(stderr,"Could not find user %s\n",sw_user);
		exit(1);
	}
	setgid(pw->pw_gid);
	setuid(pw->pw_uid);
	
	server_run(port, timeout, zipf);
}

