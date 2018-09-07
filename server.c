#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <sys/xattr.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ssyscalls.h"

#define BACKLOG 10
// #define mpath "/home/vagrant/code/final/ss"
#define min(a, b) (a < b ? a : b)
#define max(a, b) (a > b ? a : b)
#define HASH_CHUNK 32768

char mpath[MAX_PATH_LEN];
int port;

void get_hash(int fd, unsigned char *storage, char *path)
{
	struct stat st;
	stat(path, &st);
	int size = st.st_size;

	int i, dread, tored, pos = 0, space = min(size, HASH_CHUNK);
	char *buffer = malloc(space);

	unsigned char hash[SHA_DIGEST_LENGTH];

	while (size > 0)
	{
		tored = min(size, HASH_CHUNK);
		dread = pread(fd, buffer, tored, pos);
		size -= dread;
		pos += dread;

		SHA1(buffer, dread, hash);

		for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		{
			storage[i] = storage[i] ^ hash[i];
		}
	}
}

void sys_open(int cfd, int len, int flags)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);

	int rv[2], i;

	rv[1] = open(buff, O_RDWR);

	printf("open %d p:%s errno:%d\n", rv[1], buff, errno);
	if (rv[1] == -1)
	{
		rv[0] = errno;
		rv[1] = -1;
		write(cfd, rv, sizeof(rv));
		return;
	}

	unsigned char hash_prev[SHA_DIGEST_LENGTH];
	unsigned char hash[SHA_DIGEST_LENGTH];
	memset(hash_prev, 0, SHA_DIGEST_LENGTH);
	get_hash(rv[1], hash_prev, buff);

	int zzz = getxattr(buff, "user.hash", hash, SHA_DIGEST_LENGTH);

	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		if (hash_prev[i] != hash[i])
		{
			rv[1] = HASH_ERROR;
		}
	}

	close(rv[1]);

	write(cfd, rv, sizeof(rv));
	write(cfd, hash, SHA_DIGEST_LENGTH);
}

void sys_read(int cfd, int len, int size, int offset)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);
	int fd = open(buff, O_RDONLY);

	// char buf[size];
	char buf[CHUNK_SIZE];

	int szof[2] = {0, 0}, res = 0, rv[2] = {0, 0};
	read(cfd, &szof, sizeof(szof));
	size = szof[0];
	offset = szof[1];

	while (size)
	{
		// read(cfd, buf, size);
		res = pread(fd, buf, size, offset);
		if (res == -1)
		{
			rv[1] = -1;
			rv[0] = errno;
			res = 0;
		}
		write(cfd, &res, sizeof(res));
		write(cfd, buf, res);

		read(cfd, &szof, sizeof(szof));
		size = szof[0];
		offset = szof[1];
	}

	write(cfd, rv, sizeof(rv));
	printf("read fd:%d size:%d off:%d res:%d\n", fd, size, offset, res);

	close(fd);
	// free(buf);
}

void sys_write(int cfd, int len, int size, int offset)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);
	int fd = open(buff, O_RDWR);
	char buf[CHUNK_SIZE];

	int szof[2] = {0, 0}, cnt = 0;
	read(cfd, &szof, sizeof(szof));
	size = szof[0];
	offset = szof[1];

	while (size)
	{
		read(cfd, buf, size);
		cnt += pwrite(fd, buf, size, offset);
		read(cfd, &szof, sizeof(szof));
		size = szof[0];
		offset = szof[1];
	}

	// read(cfd, buf, size);

	int rv[2] = {0, 0};
	errno = 0;
	rv[1] = cnt;

	if (rv[1] < 0)
	{
		rv[0] = errno;
	}
	else
	{
		unsigned char hash[SHA_DIGEST_LENGTH];
		memset(hash, 0, SHA_DIGEST_LENGTH);
		get_hash(fd, hash, buff);
		// int zzz = getxattr(buff, "user.hash", hash, SHA_DIGEST_LENGTH);
		int zzzz = setxattr(buff, "user.hash", hash, SHA_DIGEST_LENGTH, 0);
	}
	printf("write fd:%d size:%d off:%d res:%d errno:%s\n", fd, size, offset, rv[1], strerror(errno));
	write(cfd, rv, sizeof(rv));
	close(fd);
	// free(buf);
}

void sys_release(int cfd, int len)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);

	int rv[2] = {0, 0};
	// rv[1] = close(fd);

	printf("release %s\n", buff);
	if (rv[1] == -1)
	{
		rv[0] = errno;
	}

	write(cfd, rv, sizeof(rv));
}

void sys_rename(int cfd, int flen, int tlen)
{
	errno = 0;
	char fbuff[MAX_PATH_LEN];
	strcpy(fbuff, mpath);
	read(cfd, fbuff + strlen(mpath), flen);

	char tbuff[MAX_PATH_LEN];
	strcpy(tbuff, mpath);
	read(cfd, tbuff + strlen(mpath), tlen);

	printf("rename %s   %s\n", fbuff, tbuff);
	int rv[2] = {0, 0};
	rv[1] = rename(fbuff, tbuff);

	if (rv[1] == -1)
	{
		rv[0] = errno;
	}

	write(cfd, rv, sizeof(rv));
}

void sys_unlink(int cfd, int len)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);

	int rv[2] = {0, 0};

	rv[1] = unlink(buff);
	printf("unlink %s\n", buff);
	if (rv[1] == -1)
	{
		rv[0] = errno;
	}

	write(cfd, rv, sizeof(rv));
}

void sys_rmdir(int cfd, int len)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);

	int rv[2] = {0, 0};

	rv[1] = rmdir(buff);
	printf("rmdir %s\n", buff);
	if (rv[1] == -1)
	{
		rv[0] = errno;
	}

	write(cfd, rv, sizeof(rv));
}

void sys_mkdir(int cfd, int len, mode_t mode)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);

	int rv[2] = {0, 0};

	rv[1] = mkdir(buff, mode);
	printf("mkdir %s mode:%d\n", buff, mode);
	if (rv[1] == -1)
	{
		rv[0] = errno;
	}

	write(cfd, rv, sizeof(rv));
}

void sys_readdir(int cfd, int len)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);

	DIR *dp;
	struct dirent *de;
	int rv[3];

	dp = opendir(buff);
	if (dp == NULL)
	{
		rv[0] = -1;
		rv[1] = errno;
	}
	else
	{
		while ((de = readdir(dp)) != NULL)
		{
			rv[0] = de->d_ino;
			rv[1] = de->d_type << 12;
			rv[2] = strlen(de->d_name) + 1;
			write(cfd, rv, sizeof(rv));
			write(cfd, de->d_name, strlen(de->d_name) + 1);
			rv[0] = 0;
		}
	}

	write(cfd, rv, sizeof(rv));

	closedir(dp);
}

void sys_getattr(int cfd, int len)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);
	printf("getattr %s\n", buff);

	struct stat stbuf;
	int rv[2] = {0, 0};
	rv[1] = lstat(buff, &stbuf);

	if (rv[1] == -1)
	{
		rv[0] = errno;
	}

	write(cfd, &stbuf, sizeof(struct stat));
	write(cfd, rv, sizeof(rv));
}

void sys_mknod(int cfd, int len, mode_t mode, dev_t rdev)
{

	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);
	printf("mknod %s mode:%d rdev:%ld\n", buff, mode, rdev);

	int rv[2] = {0, 0};

	/* On Linux this could just be 'mknod(mpath, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode))
	{
		rv[1] = open(buff, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (rv[1] >= 0)
		{
			unsigned char hash[SHA_DIGEST_LENGTH];
			memset(hash, 0, SHA_DIGEST_LENGTH);
			int zzz = setxattr(buff, "user.hash", hash, SHA_DIGEST_LENGTH, 0);
			if (zzz < 0)
			{
				printf("Oh dear, something went wrong with read()! %s\n", strerror(errno));
			}
			else
			{
				printf("set hash 0 r:%d\n", zzz);
			}
			rv[1] = close(rv[1]);
		}
	}
	else if (S_ISFIFO(mode))
		rv[1] = mkfifo(buff, mode);
	else
		rv[1] = mknod(buff, mode, rdev);
	if (rv[1] == -1)
		rv[0] = errno;

	write(cfd, rv, sizeof(rv));
}

void sys_utimens(int cfd, int len, long t0s, long t0ns, long t1s, long t1ns)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);
	printf("utimens %s t0s:%ld t0ns:%ld t1s:%ld t1ns:%ld\n", buff, t0s, t0ns, t1s, t1ns);

	int rv[2] = {0, 0};
	struct timeval tv[2];

	tv[0].tv_sec = t0s;
	tv[0].tv_usec = t0ns;
	tv[1].tv_sec = t1s;
	tv[1].tv_usec = t1ns;

	rv[1] = utimes(buff, tv);
	if (rv[1] == -1)
		rv[0] = errno;

	write(cfd, rv, sizeof(rv));
}

void sys_truncate(int cfd, int len, int size)
{
	errno = 0;
	char buff[MAX_PATH_LEN];
	strcpy(buff, mpath);
	read(cfd, buff + strlen(mpath), len);
	printf("truncate %s\n", buff);

	int rv[2] = {0, 0};

	rv[1] = truncate(buff, size);
	if (rv[1] == -1)
		rv[0] = errno;

	write(cfd, rv, sizeof(rv));
}

void sys_check(int cfd)
{
	int rv = 1;
	write(cfd, &rv, sizeof(rv));
	printf("check\n");
}

void sys_send_tar_gz(int cfd)
{

	char command[MAX_PATH_LEN];
	snprintf(command, MAX_PATH_LEN, "cd %s && tar --xattrs -zcvf im.in.that.745.tar.gz .", mpath);
	printf("com: %s\n", command);
	system(command);

	// char buff[MAX_PATH_LEN];
	// strcpy(buff, mpath);
	// strcat(buff, "/../im.in.that.745.tar.gz");

	// int fd = open(buff, O_RDONLY);

	// struct stat st;
	// stat(buff, &st);
	// int size = st.st_size;

	// write(cfd, &size, sizeof(size));

	// int i, dread, tored, pos = 0, space = min(size, RWCHUNK);
	// char *buffer = malloc(space);

	// unsigned char hash[SHA_DIGEST_LENGTH];

	// while (size > 0)
	// {
	// 	tored = min(size, RWCHUNK);
	// 	dread = pread(fd, buffer, tored, pos);
	// 	write(cfd, buffer, dread);
	// 	size -= dread;
	// 	pos += dread;
	// }

	// snprintf(command, MAX_PATH_LEN, "rm %s/im.in.that.745.tar.gz", mpath);
	// printf("com: %s\n", command);
	// system(command);
}

void sys_recive_tar_gz(int cfd)
{
	char command[MAX_PATH_LEN];
	snprintf(command, MAX_PATH_LEN, "cd %s && tar --xattrs -xvzf im.in.that.745.tar.gz && rm im.in.that.745.tar.gz", mpath);
	printf("com: %s\n", command);
	system(command);
}

void client_handler(int cfd)
{
	while (1)
	{
		int info[INFO_SIZE];

		read(cfd, info, sizeof(int) * INFO_SIZE);

		switch (info[0])
		{
		case open_num:
			sys_open(cfd, info[1], info[2]);
			break;
		case read_num:
			sys_read(cfd, info[1], info[2], info[3]);
			break;
		case write_num:
			sys_write(cfd, info[1], info[2], info[3]);
			break;
		case release_num:
			sys_release(cfd, info[1]);
			break;
		case rename_num:
			sys_rename(cfd, info[1], info[2]);
			break;
		case unlink_num:
			sys_unlink(cfd, info[1]);
			break;
		case rmdir_num:
			sys_rmdir(cfd, info[1]);
			break;
		case mkdir_num:
			sys_mkdir(cfd, info[1], info[2]);
			break;
		case readdir_num:
			sys_readdir(cfd, info[1]);
			break;
		case getattr_num:
			sys_getattr(cfd, info[1]);
			break;
		case mknod_num:
			sys_mknod(cfd, info[1], info[2], info[3]);
			break;
		case utimens_num:
			sys_utimens(cfd, info[1], info[2], info[3], info[4], info[5]);
			break;
		case truncate_num:
			sys_truncate(cfd, info[1], info[2]);
			break;
		case check_num:
			sys_check(cfd);
			break;
		case send_tar_gz_num:
			sys_send_tar_gz(cfd);
			break;
		case recive_tar_gz_num:
			sys_recive_tar_gz(cfd);
			break;

		default:
			break;
		}
	}
	close(cfd);
	exit(0);
}

int main(int argc, char *argv[])
{
	int sfd, cfd;
	struct sockaddr_in addr;
	struct sockaddr_in peer_addr;
	strcpy(mpath, argv[3]);
	sscanf(argv[2], "%i", &port);
	printf("%s\n", mpath);
	char *ip = argv[1];

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	int optval = 1;
	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_aton(ip, &(addr.sin_addr));
	// addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	listen(sfd, BACKLOG);

	while (1)
	{
		int peer_addr_size = sizeof(struct sockaddr_in);
		cfd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_size);
		switch (fork())
		{
		case -1:
			exit(100);
		case 0:
			close(sfd);
			client_handler(cfd);
			exit(0);
		default:
			close(cfd);
		}
	}
	close(sfd);
}
