
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

#ifndef LLONG_MAX
	#define LLONG_MAX 2094967295
#endif

#define RTYPE_404    0
#define RTYPE_DIR    1
#define RTYPE_FIL    2
#define RTYPE_405    3
#define RTYPE_403    4
#define RTYPE_PROXY  5

void urldecode (char * dest, const char *url);

#define RETURN_STRBUF(task, buffer) \
	{ \
		strcpy((char*)task->request_data, (char*)buffer); \
		task->request_size = strlen((char*)buffer); \
	}

// writes to param_str the value of the parameter in the request trimming whitespaces
static char param_str[REQUEST_MAX_SIZE*3];
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

unsigned generate_dir_entry(void * out, const struct dirent * ep) {
	const char * slash = ep->d_type == DT_DIR ? "/" : "";
	#ifdef HTMLLIST
		sprintf((char*)out, "<a href=\"%s%s\">%s%s</a><br>\n", ep->d_name, slash, ep->d_name, slash);
	#else
		sprintf((char*)out, "%s%s\n", ep->d_name, slash);
	#endif
	return strlen((char*)out);
}

unsigned dirlist_size(const char * file_path) {
	char tmp[4*1024];
	unsigned r = 0;
	DIR * d = opendir(file_path);
	while (1) {
		struct dirent *ep = readdir(d);
		if (!ep) break;

		r += generate_dir_entry(tmp, ep);
	}
	closedir(d);
	return r;
}

int parse_range_req(const char * req_val, long long * start, long long * end) {
	// Req_val will be something like:
	// bytes=120-   (download from byte 120 to the end)
	// bytes=-120   (download the last 120 bytes)
	// bytes=120-123 (interval)
	// bytes=1-2,5-6 (multiple chunks)
	// We only support %- or %-%
	
	// By default whole file
	*start = 0;
	*end = LLONG_MAX;

	// Check if there's a comma!
	if (strstr(req_val,",") != 0)
		return -1;

	// Strip bytes prefix
	const char * ptr = strstr(req_val,"=");
	if (ptr == 0) ptr = req_val;
	else ptr++; //Skip "="

	// Whitespace strip
	while (*ptr == ' ') ptr++;

	if (*ptr == 0) return -1; // Empty!!!

	// Read the start
	sscanf(ptr,"%lld %*s",start);
	if (*start < 0) return -1;
	
	// Search for "-" 
	ptr = strstr(ptr,"-");
	if (ptr == 0)
		return 0;  // No "-" present, assuming EOF
	else
		ptr++;

	// More whitespace
	while (*ptr == ' ') ptr++;

	if (*ptr == 0)
		return 0;  // assuming EOF

	// Read the end
	sscanf(ptr,"%lld %*s",end);
	
	// Both should be positive values, being start >= end
	if (*end < 0 || *start > *end) return -1;

	return 0;
}

// strcpy with overlap buffers
void strcpy_o(char * dest, char * src) {
	while (*src != 0) {
		*dest++ = *src++;
	}
	*dest = 0;
}

int path_create(const char * base_path, const char * req_file, char * out_file) {
	char temp[ strlen(req_file)+1 ];
	strcpy(temp, req_file);
	
	int i,j;
	// Remove double slashes
	for (i = 0; i < (int)strlen(temp)-1; i++) {
		if (temp[i] == '/' && temp[i+1] == '/') {
			strcpy_o(&temp[i], &temp[i+1]);
			i--;
		}
	}
	// Remove .. by removing previous dir
	for (i = 0; i < (int)strlen(temp)-4; i++) {
		if (temp[i] == '/' && temp[i+1] == '.' && 
			temp[i+2] == '.' && temp[i+3] == '/') {
			
			// Remove previous folder
			for (j = i-1; j >= 0; j--) {
				if (temp[j] == '/' || j == 0) {
					strcpy_o(&temp[j], &temp[i+3]);
					i = -1;
					break;
				}
			}
		}
	}
	// Remove the remaining .. (prevent going up base_dir)
	for (i = 0; i < (int)strlen(temp)-4; i++) {
		if (temp[i] == '/' && temp[i+1] == '.' && 
			temp[i+2] == '.' && temp[i+3] == '/') {
			
			// Remove previous folder
			strcpy_o(&temp[i],&temp[i+3]);
			i--;
		}
	}
	
	if (temp[0] == '/')
		strcpy_o(&temp[0],&temp[1]);

	strcpy(out_file,base_path);
	strcat(out_file,"/");
	
	urldecode(&out_file[strlen(out_file)], temp);
	
	// If it ends as "/" it's a path, so append default file
	// (Only if it exists ofc)
	unsigned osize = strlen(out_file);
	if (out_file[strlen(out_file)-1] == '/') {
		strcat(out_file, DEFAULT_DOC);

		// Try the index first
		FILE * fd = fopen(out_file, "rb");
		if (fd) {
			fclose(fd);
			return RTYPE_FIL;
		}

		// Strip the default doc and output the dir
		out_file[osize] = 0;
	}

	// Try to open the dir
	void * ptr = opendir(out_file);
	if (ptr) {
		closedir(ptr);
		return RTYPE_DIR;
	}

	// Try as file
	FILE * fd = fopen(out_file, "rb");
	if (fd) {
		fclose(fd);
		return RTYPE_FIL;
	}

	return RTYPE_404;
}

char hex2char(const char * i) {
	char c1, c2;
	if      (i[0] >= '0' && i[0] <= '9') c1 = i[0]-'0';
	else if (i[0] >= 'a' && i[0] <= 'f') c1 = i[0]-'a'+10;
	else                                 c1 = i[0]-'A'+10;
		
	if      (i[1] >= '0' && i[1] <= '9') c2 = i[1]-'0';
	else if (i[1] >= 'a' && i[1] <= 'f') c2 = i[1]-'a'+10;
	else                                 c2 = i[1]-'A'+10;
	
	return c1*16+c2;
}
int ishexpair(const char * i) {
	if (!(	(i[0] >= '0' && i[0] <= '9') ||
		(i[0] >= 'a' && i[0] <= 'f') ||
		(i[0] >= 'A' && i[0] <= 'F') ))
		return 0;
	if (!(	(i[1] >= '0' && i[1] <= '9') ||
		(i[1] >= 'a' && i[1] <= 'f') ||
		(i[1] >= 'A' && i[1] <= 'F') ))
		return 0;
	return 1;
}

int parse_url(char * in, const char **hostname, int * port, const char ** path) {
	// URL like server.com[:port]/path/foo/bar
	while (*in != 0 && *in == '/') in++;  // Skip leading slashes
	*hostname = in;

	while (*in != 0 && *in != ':' && *in != '/') in++;
	if (*in == ':') {
		*in++ = 0;
		*port = atoi(in);
		while (*in != 0 && *in != '/') in++;
	}
	else
		*port = 80;

	if (*in == 0)
		return 0;

	*in++ = 0;
	*path = in;
	return 1;
}

void urldecode (char * dest, const char *url) {
	int s = 0, d = 0;
	int url_len = strlen (url) + 1;

	while (s < url_len) {
		char c = url[s++];

		if (c == '%' && s + 2 < url_len) {
			if (ishexpair(&url[s]))
				dest[d++] = hex2char(&url[s]);
			else {
				dest[d++] = c;
				dest[d++] = url[s+0];
				dest[d++] = url[s+1];
			}
			s += 2;
		}
		else if (c == '+') {
			dest[d++] = ' ';
		}
		else {
			dest[d++] = c;
		}
	}
}


