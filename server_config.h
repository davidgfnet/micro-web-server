
#define DEFAULT_DOC	   "index.html"  // Default doc to serve when URL points to dir
#define REQUEST_MAX_SIZE   2047          // Maximum allowed size for a GET request
#define MAX_PATH_LEN	   4096          // Maximum size (in chars) for a path in the filesystem

#define MAXCLIENTS       128             // Maximum number of simultaneous connections allowed (the bigger, the more mem used)
#define WR_BLOCK_SIZE	 (1024*1024)     // Chunk size for disk read/write operations, the bigger the more throughput

