
#define _FILE_OFFSET_BITS 64

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
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <assert.h>

#include "server_config.h"
#include "server.h"

#define STATUS_REQ         0               
#define STATUS_RESP        1
#define STATUS_PROXY       2
#define STATUS_PROXY_CON   3
#define STATUS_PROXY_REQ   4
#define STATUS_PROXY_FWD   5

const char ok_200[]  = "HTTP/1.1 200 OK\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";
const char err_401[] = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Auth needed\"\r\n\r\nConnection: close\r\n\r\n";
const char err_403[] = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
const char err_404[] = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
const char err_405[] = "HTTP/1.1 405 Method not allowed\r\nConnection: close\r\n\r\n";
const char err_413[] = "HTTP/1.1 413 Request Entity Too Large\r\nConnection: close\r\n\r\n";
const char partial_206[]  = "HTTP/1.1 206 Partial content\r\nContent-Range: bytes %lld-%lld/%lld\r\nContent-Length: %lld\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";

const char dirlist_200_txt[]  = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %u\r\nX-Directory: true\r\nConnection: close\r\n\r\n";
const char dirlist_200_html[]  = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %u\r\nX-Directory: true\r\nConnection: close\r\n\r\n";

char tbuffer[WR_BLOCK_SIZE];  // Temporary buffer for main thread usage
char auth_str[128];           // eg. "Basic dXNlcjpwYXNz";

struct process_task {
	int fd;
	FILE* fdfile;
	long start_time;
	char status;
	int offset;
	long long fend;
	unsigned short request_size;
	unsigned char request_data[REQUEST_MAX_SIZE+1];
	DIR *dirlist;
	int remotefd, remoteport;

	// List of free/nonfree tasks
	struct process_task * next;
};
int listenfd, epollfd;
struct process_task tasks[MAXCLIENTS];
struct process_task * free_task = &tasks[0];

#ifdef HTTP_PROXY_ENABLED
#include "tadns.h"
struct dns * dnsinstance;
#endif

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

long long lof(FILE * fd) {
	long long pos = ftello(fd);
	fseeko(fd,0,SEEK_END);
	long long len = ftello(fd);
	fseeko(fd,pos,SEEK_SET);
	return len;
}

void cleanup_task(struct process_task * t) {
	epoll_ctl(epollfd, EPOLL_CTL_DEL, t->fd, NULL);
	epoll_ctl(epollfd, EPOLL_CTL_DEL, t->remotefd, NULL);

	if (t->dirlist) {
		closedir(t->dirlist);
		t->dirlist = 0;
	}
	if (t->fdfile) {
		fclose(t->fdfile);
		t->fdfile = 0;
	}
	if (t->fd >= 0) {
		close(t->fd);
		t->fd = -1;
	}
	if (t->remotefd >= 0) {
		close(t->remotefd);
		t->remotefd = -1;
	}
	#ifdef HTTP_PROXY_ENABLED
	// Try to cancel DNS req, even there is no inflight req
	dns_cancel(dnsinstance, t);
	#endif
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

#ifdef HTTP_PROXY_ENABLED
void dnscallback(struct dns_cb_data * cbd) {
	struct process_task * t = (struct process_task *)cbd->context;

	if (cbd->error != DNS_OK) {
		// Force timeout
		t->start_time = 0;
		return;
	}

	time(&t->start_time);

	// Start connection
	t->remotefd = socket(AF_INET, SOCK_STREAM, 0);
	setNonblocking(listenfd);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(t->remoteport);
	memcpy(&addr.sin_addr.s_addr, cbd->addr, 4);
	int r = connect(t->remotefd, (const struct sockaddr*)&addr, sizeof(addr));
	if (r < 0 && errno != EINPROGRESS) {
		t->start_time = 0;
		return;
	}

	t->status = STATUS_PROXY_CON;
	epollupdate(t->remotefd, POLLOUT, t);
}

int work_proxy(struct process_task * t) {
	if (t->remotefd >= 0) {
		if (t->status == STATUS_PROXY_CON) {
			int result;
			socklen_t result_len = sizeof(result);
			if (getsockopt(t->remotefd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0)
				return 1;
			t->status = STATUS_PROXY_REQ;
		}
		if (t->status == STATUS_PROXY_REQ) {
			// Keep sending request to the remote host
			int w = write(t->remotefd, &t->request_data[t->offset], t->request_size - t->offset);
			if (w >= 0) {
				t->offset += w;
				if (w > 0)
					time(&t->start_time);

				if (t->offset == t->request_size) {
					t->status = STATUS_PROXY_FWD;
					epollupdate(t->remotefd, POLLIN, t);
				}
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK)
				return 1;
		}
		if (t->status == STATUS_PROXY_FWD) {
			if (t->request_size == t->offset) {
				int r = read(t->remotefd, t->request_data, REQUEST_MAX_SIZE);
				if (r > 0) {
					t->request_size = r;
					t->offset = 0;
					time(&t->start_time);

					epollupdate(t->fd, POLLOUT, t);
					epoll_ctl(epollfd, EPOLL_CTL_DEL, t->remotefd, NULL);
				}
				else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
					return 1;
			}
			if (t->request_size != t->offset) {
				int w = write(t->fd, &t->request_data[t->offset], t->request_size - t->offset);
				if (w >= 0) {
					t->offset += w;
					if (w > 0)
						time(&t->start_time);

					if (t->request_size == t->offset) {
						epollupdate(t->remotefd, POLLIN, t);
						epoll_ctl(epollfd, EPOLL_CTL_DEL, t->fd, NULL);
					}
				}
				else if (errno != EAGAIN && errno != EWOULDBLOCK)
					return 1;
			}
		}
	}

	return 0;
}
#endif

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

int work_request(struct process_task * t, const char * base_path, int dirlist, int beproxy) {
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

			// Parse the request header			
			int userange = 1;
			long long fstart = 0;
			if (header_attr_lookup((char*)t->request_data, "Range:", "\r\n") < 0) {
				userange = 0;
				t->fend = LLONG_MAX;
			}else{
				if (parse_range_req(param_str,&fstart,&t->fend) < 0) {
					userange = 0;
					fstart = 0;
					t->fend = LLONG_MAX;
				}
			}

			if (!check_auth(t))
				RETURN_STRBUF(t, err_401);

			int ishead = 0;
			int isget = header_attr_lookup((char*)t->request_data, "GET ", " ") >= 0; // Get the file
			if (!isget)
				ishead = header_attr_lookup((char*)t->request_data, "HEAD ", " ") >= 0; // Get the file
			char file_path[MAX_PATH_LEN*2];
			int code = beproxy ? RTYPE_PROXY : path_create(base_path, param_str, file_path);
			if (!isget && !ishead) code = RTYPE_405;
			if (code == RTYPE_DIR && !dirlist) code = RTYPE_403;

			switch (code) {
			case RTYPE_403: RETURN_STRBUF(t, err_403);
			case RTYPE_404: RETURN_STRBUF(t, err_404);
			case RTYPE_405: RETURN_STRBUF(t, err_405);
			case RTYPE_DIR:  // Dir
				if (!ishead)
					t->dirlist = opendir(file_path);
				#ifdef HTMLLIST
					sprintf((char*)t->request_data, dirlist_200_html, dirlist_size(file_path));
				#else
					sprintf((char*)t->request_data, dirlist_200_txt, dirlist_size(file_path));
				#endif
				t->request_size = strlen((char*)t->request_data);
				break;
			case RTYPE_FIL:{// File
				FILE * fd = fopen(file_path,"rb");
				long long len = lof(fd);
				const char * mimetype = mime_lookup(file_path);
				if (t->fend > len-1) t->fend = len-1;  // Last byte, not size
				long long content_length = t->fend - fstart + 1;

				if (userange && isget) {
					sprintf((char*)t->request_data, partial_206, fstart, t->fend, len,content_length, mimetype);
					t->request_size = strlen((char*)t->request_data);
				}else{
					sprintf((char*)t->request_data, ok_200, content_length, mimetype);
					t->request_size = strlen((char*)t->request_data);
				}

				if (ishead) {
					fclose(fd);
				} else {
					t->fdfile = fd;
					fseeko(fd, fstart, SEEK_SET); // Seek the first byte
				}
				}break;

			#ifdef HTTP_PROXY_ENABLED
			case RTYPE_PROXY:{
				t->status = STATUS_PROXY;

				urldecode(file_path, param_str);
				const char *hostname, *path;
				if (parse_url(file_path, &hostname, &t->remoteport, &path)) {
					// Prepare request
					sprintf((char*)t->request_data, "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
					t->request_size = strlen((char*)t->request_data);
					t->offset = 0;
					dns_queue(dnsinstance, t, hostname, DNS_A_RECORD, dnscallback);
					epoll_ctl(epollfd, EPOLL_CTL_DEL, t->fd, NULL);
				};
				} break;
			#endif
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
			int toread = WR_BLOCK_SIZE;
			if (toread > (t->fend + 1 - ftello(t->fdfile))) toread = (t->fend + 1 - ftello(t->fdfile));
			if (toread < 0) toread = 0; // File could change its size...

			int numb = fread(tbuffer,1,toread,t->fdfile);
			if (numb > 0) {
				// Try to write the data to the socket
				int bwritten = write(t->fd,tbuffer,numb);

				// Seek back if necessary
				int bw = bwritten >= 0 ? bwritten : 0;
				fseek(t->fdfile,-numb+bw,SEEK_CUR);

				if (bwritten >= 0) {
					time(&t->start_time);   // Update timeout
				}
				else if (errno != EAGAIN && errno != EWOULDBLOCK)
					return 1;  // Some unknown error!
			}
			else  // Error or end of file
				return 1;
		} else if (t->dirlist) {
			struct dirent *ep = readdir(t->dirlist);
			if (ep) {
				t->request_size = generate_dir_entry(t->request_data, ep);
				t->offset = 0;
			} else {
				closedir(t->dirlist);
				t->dirlist = 0;
				return 1;
			}
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

void server_run (int port, int ctimeout, char * base_path, int dirlist, int beproxy) {
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

	#ifdef HTTP_PROXY_ENABLED
	epollupdate(dns_get_fd(dnsinstance), POLLIN, NULL);
	#endif
	epollupdate(listenfd, POLLIN, NULL);

	while (1) {
		// Unblock if more than 1 second have elapsed (to allow killing dead connections)
		struct epoll_event revents[MAXCLIENTS];
		int nev = epoll_wait(epollfd, revents, MAXCLIENTS, 1000);

		// DNS query
		#ifdef HTTP_PROXY_ENABLED
		dns_poll(dnsinstance);
		#endif

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
				t->dirlist = 0;
				t->offset = 0;
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
				force_end |= work_request(t, base_path, dirlist, beproxy);

			#ifdef HTTP_PROXY_ENABLED
			if ((t->status == STATUS_PROXY || t->status == STATUS_PROXY_REQ ||
				 t->status == STATUS_PROXY_FWD || t->status == STATUS_PROXY_CON) && !force_end)
				force_end |= work_proxy(t);
			#endif

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
	int port = 8080, timeout = 8, dirlist = 0, beproxy = 0;
	char base_path[MAX_PATH_LEN] = {0};
	getcwd(base_path, MAX_PATH_LEN-1);
	char sw_user[256] = "nobody";

	int i;
	for (i = 1; i < argc; i++) {
		// Port
		if (strcmp(argv[i],"-p") == 0)
			sscanf(argv[++i], "%d", &port);
		// Timeout
		if (strcmp(argv[i],"-t") == 0)
			sscanf(argv[++i], "%d", &timeout);
		// Base dir
		if (strcmp(argv[i],"-d") == 0)
			strcpy(base_path, argv[++i]);
		// Dir list
		if (strcmp(argv[i],"-l") == 0)
			dirlist = 1;
		// User drop
		if (strcmp(argv[i],"-u") == 0)
			strcpy(sw_user, argv[++i]);
		// Auth
		if (strcmp(argv[i],"-a") == 0)
			strcpy(auth_str, argv[++i]);
		// URL proxy
		#ifdef HTTP_PROXY_ENABLED
		if (strcmp(argv[i],"-x") == 0)
			beproxy = 1;
		#endif
		// Help
		if (strcmp(argv[i],"-h") == 0) {
			printf("Usage: server [-p port] [-t timeout] [-d base_dir] [-u user]\n"
			"    -p     Port             (Default port is 8080)\n"
			"    -t     Timeout          (Default timeout is 8 seconds of network inactivity)\n"
			"    -d     Base Dir         (Default dir is working dir)\n"
			"    -l     Enable dir lists (Off by default for security reasons)\n"
			"    -u     Switch to user   (Switch to specified user (may drop privileges, by default nobody))\n"
			"    -a     HTTP Auth        (Specify an auth string, i.e. \"Basic dXNlcjpwYXNz\")\n"
			#ifdef HTTP_PROXY_ENABLED
			"    -x     URL proxy        (This disables the file serving)\n"
			#endif
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

	#ifdef HTTP_PROXY_ENABLED
	dnsinstance = dns_init();
	#endif
	
	server_run(port, timeout, base_path, dirlist, beproxy);
}

