
#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <pthread.h>

#include "ssyscalls.h"

#define PATH "/home/vagrant/code/final/ss"
#define min(a, b) (a < b ? a : b)
typedef int bool;
enum
{
	false,
	true
};

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int primary_sfd;
int secondary_sfd;
int hotswap_sfd;
int logfd;

char ip[20] = "127.0.0.1";
int first_port, second_port, hot_port;

int get_connection(char *ipstr, int port)
{
	signal(SIGPIPE, SIG_IGN);
	struct sockaddr_in addr;
	int ip;
	int sfd = socket(AF_INET, SOCK_STREAM, 0);
	inet_pton(AF_INET, ipstr, &ip);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ip;

	connect(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

	return sfd;
}

int send_info_path(int sfd, int *info, const char *path)
{
	send(sfd, info, sizeof(int) * INFO_SIZE, MSG_NOSIGNAL);
	return send(sfd, path, info[1], MSG_NOSIGNAL);
}

int get_rv(int sfd, bool return_zero)
{
	int rv[2];
	read(sfd, rv, sizeof(rv));

	if (rv[1] == -1)
	{
		errno = rv[0];
		return -errno;
	}
	else
	{
		return (return_zero ? 0 : rv[1]);
	}
}

void move_file(int sfd_from, int sfd_to, const char *path)
{
	struct stat stbuf;
	int info[INFO_SIZE] = {getattr_num, strlen(path) + 1, 0, 0, 0, 0};
	send_info_path(sfd_from, info, path);
	read(sfd_from, &stbuf, sizeof(struct stat));
	get_rv(sfd_from, true);
	int size = stbuf.st_size, tored, dread, pos = 0;
	char *buffer = malloc(RWCHUNK);

	int info1[INFO_SIZE] = {unlink_num, strlen(path) + 1, 0, 0, 0, 0};
	send_info_path(sfd_to, info1, path);
	get_rv(sfd_to, true);

	int info2[INFO_SIZE] = {mknod_num, strlen(path) + 1, stbuf.st_mode, stbuf.st_rdev, 0, 0};
	send_info_path(sfd_to, info2, path);
	get_rv(sfd_to, true);

	while (size > 0)
	{
		tored = min(size, RWCHUNK);
		// read
		int info3[INFO_SIZE] = {read_num, strlen(path) + 1, tored, pos, 0, 0};
		send_info_path(sfd_from, info3, path);
		int rv[2];
		read(sfd_from, rv, sizeof(rv));

		if (rv[1] == -1)
		{
			errno = rv[0];
			return;
		}

		if (rv[1] > 0)
			read(sfd_from, buffer, rv[1]);

		dread = rv[1];

		int info4[INFO_SIZE] = {write_num, strlen(path) + 1, dread, pos, 0, 0};
		send_info_path(sfd_to, info4, path);
		send(sfd_to, buffer, size, MSG_NOSIGNAL);
		get_rv(sfd_to, false);

		size -= dread;
		pos += dread;
	}
}

static int do_open(const char *path, struct fuse_file_info *fi)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {open_num, strlen(path) + 1, fi->flags, 0, 0, 0}, i;
	send_info_path(primary_sfd, info, path);
	send_info_path(secondary_sfd, info, path);

	int rv1 = get_rv(primary_sfd, false);
	int rv2 = get_rv(secondary_sfd, false);

	unsigned char hash1[SHA_DIGEST_LENGTH];
	unsigned char hash2[SHA_DIGEST_LENGTH];

	// if one ot the server does not contain file, just copy it from the other one
	if (rv1 == -ENOENT)
	{
		read(secondary_sfd, hash2, SHA_DIGEST_LENGTH);
		move_file(secondary_sfd, primary_sfd, path);
	    pthread_mutex_unlock(&mutex);
		return 0;
	}

	if (rv2 == -ENOENT)
	{
		read(primary_sfd, hash1, SHA_DIGEST_LENGTH);
		move_file(primary_sfd, secondary_sfd, path);
	    pthread_mutex_unlock(&mutex);
		return 0;
	}

	int pup, sup; // primary up and secondary up. 0 means that server is down.

	pup = read(primary_sfd, hash1, SHA_DIGEST_LENGTH);
	sup = read(secondary_sfd, hash2, SHA_DIGEST_LENGTH);

	if (pup * sup <= 0)
	{
	    pthread_mutex_unlock(&mutex);
		return 0;
	}

	if (rv1 == HASH_ERROR)
	{
		move_file(secondary_sfd, primary_sfd, path);
	}
	else
	{
		if (rv2 == HASH_ERROR)
		{
			move_file(primary_sfd, secondary_sfd, path);
		}
		else
		{

			for (i = 0; i < SHA_DIGEST_LENGTH; i++)
			{
				if (hash1[i] != hash2[i])
				{
					struct stat st1;
					struct stat st2;
					int info2[INFO_SIZE] = {getattr_num, strlen(path) + 1, 0, 0, 0, 0};
					send_info_path(primary_sfd, info2, path);
					send_info_path(secondary_sfd, info2, path);
					read(primary_sfd, &st1, sizeof(struct stat));
					read(secondary_sfd, &st2, sizeof(struct stat));
					get_rv(primary_sfd, true);
					get_rv(secondary_sfd, true);

					if (st1.st_mtime > st2.st_mtime)
					{
						move_file(primary_sfd, secondary_sfd, path);
					}
					else
					{
						move_file(secondary_sfd, primary_sfd, path);
					}

					break;
				}
			}
		}
	}

	pthread_mutex_unlock(&mutex);
	return 0;
}

static int do_read(const char *path, char *buf, size_t size, off_t offset,
				   struct fuse_file_info *fi)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {read_num, strlen(path) + 1, size, offset, 0, 0};
	send_info_path(primary_sfd, info, path);

	int rv[2];
	read(primary_sfd, rv, sizeof(rv));

	if (rv[1] == -1)
	{
		errno = rv[0];
		pthread_mutex_unlock(&mutex);
		return -errno;
	}

	if (rv[1] > 0)
		read(primary_sfd, buf, rv[1]);

	pthread_mutex_unlock(&mutex);
	return rv[1];
}

static int do_write(const char *path, const char *buf, size_t size,
					off_t offset, struct fuse_file_info *fi)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {write_num, strlen(path) + 1, size, offset, 0, 0};
	send_info_path(primary_sfd, info, path);
	send_info_path(secondary_sfd, info, path);
	send(primary_sfd, buf, size, MSG_NOSIGNAL);
	send(secondary_sfd, buf, size, MSG_NOSIGNAL);

	get_rv(secondary_sfd, false);
	int ret = get_rv(primary_sfd, false);
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int do_release(const char *path, struct fuse_file_info *fi)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {release_num, strlen(path) + 1, 0, 0, 0, 0};
	send_info_path(primary_sfd, info, path);

	int ret = get_rv(primary_sfd, true);
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int do_rename(const char *from, const char *to)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {rename_num, strlen(from) + 1, strlen(to) + 1, 0, 0, 0};
	send_info_path(primary_sfd, info, from);
	send_info_path(secondary_sfd, info, from);
	send(primary_sfd, to, strlen(to) + 1, MSG_NOSIGNAL);
	send(secondary_sfd, to, strlen(to) + 1, MSG_NOSIGNAL);

	get_rv(secondary_sfd, true);
	int ret = get_rv(primary_sfd, true);
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int do_unlink(const char *path)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {unlink_num, strlen(path) + 1, 0, 0, 0, 0};
	send_info_path(primary_sfd, info, path);
	send_info_path(secondary_sfd, info, path);

	get_rv(secondary_sfd, true);
	int ret = get_rv(primary_sfd, true);
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int do_rmdir(const char *path)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {rmdir_num, strlen(path) + 1, 0, 0, 0, 0};
	send_info_path(primary_sfd, info, path);
	send_info_path(secondary_sfd, info, path);

	get_rv(secondary_sfd, true);
	int ret = get_rv(primary_sfd, true);
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int do_mkdir(const char *path, mode_t mode)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {mkdir_num, strlen(path) + 1, mode, 0, 0, 0};
	send_info_path(primary_sfd, info, path);
	send_info_path(secondary_sfd, info, path);

	get_rv(secondary_sfd, true);
	int ret = get_rv(primary_sfd, true);
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int do_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
					  off_t offset, struct fuse_file_info *fi)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {readdir_num, strlen(path) + 1, 0, 0, 0, 0};
	send_info_path(primary_sfd, info, path);

	int rv[3];
	read(primary_sfd, rv, sizeof(rv));

	while (rv[0] != 0)
	{
		if (rv[0] == -1)
		{
			errno = rv[1];
			pthread_mutex_unlock(&mutex);
			return -errno;
		}
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = rv[0];
		st.st_mode = rv[1];
		char name[rv[2]];
		read(primary_sfd, name, rv[2]);
		filler(buf, name, &st, 0);
		read(primary_sfd, rv, sizeof(rv));
	}

	pthread_mutex_unlock(&mutex);
	return 0;
}

static int do_getattr(const char *path, struct stat *stbuf)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {getattr_num, strlen(path) + 1, 0, 0, 0, 0};
	send_info_path(primary_sfd, info, path);

	read(primary_sfd, stbuf, sizeof(struct stat));

	int rv = get_rv(primary_sfd, true);
	// timer_function(NULL);
	pthread_mutex_unlock(&mutex);
	return rv;
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {mknod_num, strlen(path) + 1, mode, rdev, 0, 0};
	send_info_path(primary_sfd, info, path);
	send_info_path(secondary_sfd, info, path);

	get_rv(secondary_sfd, true);
	int ret = get_rv(primary_sfd, true);
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int do_utimens(const char *path, const struct timespec ts[2])
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {utimens_num, strlen(path) + 1, ts[0].tv_sec, ts[0].tv_nsec / 1000, ts[1].tv_sec, ts[1].tv_nsec / 1000};
	send_info_path(primary_sfd, info, path);
	send_info_path(secondary_sfd, info, path);

	get_rv(secondary_sfd, true);
	int ret = get_rv(primary_sfd, true);
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int do_truncate(const char *path, off_t size)
{
	pthread_mutex_lock(&mutex);
	int info[INFO_SIZE] = {truncate_num, strlen(path) + 1, size, 0, 0, 0};
	send_info_path(primary_sfd, info, path);
	send_info_path(secondary_sfd, info, path);

	get_rv(secondary_sfd, true);
	int ret = get_rv(primary_sfd, true);
	pthread_mutex_unlock(&mutex);
	return ret;
}

void *timer_function(void *x_void_ptr)
{
	int cnt = 0;
	int info[INFO_SIZE] = {check_num, 0, 0, 0, 0, 0}, rv, prv, srv;
	while (true)
	{
		pthread_mutex_lock(&mutex);
		send(primary_sfd, info, sizeof(int) * INFO_SIZE, MSG_NOSIGNAL);
		prv = read(primary_sfd, &rv, sizeof(rv));

		if (prv <= 0)
		{
			int tmp = secondary_sfd;
			secondary_sfd = primary_sfd;
			primary_sfd = tmp;

			tmp = second_port;
			second_port = first_port;
			first_port = tmp;
		}

		send(secondary_sfd, info, sizeof(int) * INFO_SIZE, MSG_NOSIGNAL);
		srv = read(secondary_sfd, &rv, sizeof(rv));

		if (srv <= 0)
		{
			cnt++;
			secondary_sfd = get_connection(ip, second_port);
		}
		else
		{
			cnt = 0;
		}

		if(cnt >= 10)
		{
			int tmp = secondary_sfd;
			secondary_sfd = hotswap_sfd;
			hotswap_sfd = tmp;

			tmp = second_port;
			second_port = hot_port;
			hot_port = tmp;

			info[0] = send_tar_gz_num;
			send(primary_sfd, info, sizeof(int) * INFO_SIZE, MSG_NOSIGNAL);
			char path[32] = "/im.in.that.745.tar.gz";
			move_file(primary_sfd, secondary_sfd, path);
			info[0]= recive_tar_gz_num;
			send(secondary_sfd, info, sizeof(int) * INFO_SIZE, MSG_NOSIGNAL);
		    pthread_mutex_unlock(&mutex);
			do_unlink(path);
			pthread_mutex_lock(&mutex);
			info[0] = check_num;
		}
	    pthread_mutex_unlock(&mutex);

		sleep(1);
	}

	return NULL;
}

static struct fuse_operations do_oper = {
	.open = do_open,
	.read = do_read,
	.write = do_write,
	.release = do_release,
	.rename = do_rename,
	.unlink = do_unlink,
	.rmdir = do_rmdir,
	.mkdir = do_mkdir,
	.readdir = do_readdir,
	.getattr = do_getattr,
	.mknod = do_mknod,
	.utimens = do_utimens,
	.truncate = do_truncate,
};

int main(int argc, char *argv[])
{
	// umask(0);
	first_port = 5000;
	second_port = 5001;
	hot_port = 5003;
	primary_sfd = get_connection(ip, first_port);
	secondary_sfd = get_connection(ip, second_port);
	hotswap_sfd = get_connection(ip, hot_port);
	pthread_t timer_thread;
	pthread_create(&timer_thread, NULL, timer_function, NULL);
	return fuse_main(argc, argv, &do_oper, NULL);
}
