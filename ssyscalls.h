#pragma once

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
	mknod_num,
	getattr_num,
	utimens_num,
	truncate_num,
	check_num,
	send_tar_gz_num,
	recive_tar_gz_num
} syscall_num;

#define HASH_ERROR -7
#define RWCHUNK 4096
#define min(a, b) (a < b ? a : b)
#define max(a, b) (a > b ? a : b)
#define HASH_CHUNK 32768
#define INFO_SIZE 6
#define MAX_PATH_LEN 1024
#define CHUNK_SIZE 256

typedef int bool;
enum
{
	false,
	true
};