
typedef enum syscall_num
{
	open_num,
	read_num,
	write_num,
	release_num,
	rename_num,
	unlink_num,
	rmdir_num,
	mkdir_num,
	readdir_num,
	releasedir_num,
	mknod_num,
	getattr_num,
	utimens_num,
	truncate_num
} syscall_num;

#define HASH_ERROR -7
#define RWCHUNK 4096
#define min(a, b) (a < b ? a : b)
#define max(a, b) (a > b ? a : b)
#define HASH_CHUNK 32768
