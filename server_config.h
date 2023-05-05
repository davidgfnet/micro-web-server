
#define DEFAULT_DOC	   "/index.html"  // Default doc to serve when URL points to dir
#define REQUEST_MAX_SIZE   2047          // Maximum allowed size for a GET request
#define MAX_PATH_LEN	   4096          // Maximum size (in chars) for a path in the filesystem

#define MAXCLIENTS       128             // Maximum number of simultaneous connections allowed (the bigger, the more mem used)
#define WR_BLOCK_SIZE	 (1024*1024)     // Chunk size for disk read/write operations, the bigger the more throughput

#define HTMLLIST                         // Directory listing is an HTML doc (as opposted to TXT)

// MIME type definition

struct mime_type {
	const char *extension;
	const char *mime_type;
} mtypes[] = {
	{"",		"application/octet-stream"},  // Default mime type
	{"htm",		"text/html"},
	{"html",	"text/html"},
	{"css",		"text/css"},
	{"gif",		"image/gif"},
	{"png",		"image/png"},
	{"js",		"application/javascript"},
	{"jpg",		"image/jpeg"},
	{"jpeg",	"image/jpeg"},
	{"bmp",		"image/bmp"},
	{"xml",		"text/xml"},
	{"mp3",		"audio/mpeg"},
	{"mod",		"video/mp4"},
	{"avi",		"video/x-msvideo"}
};


