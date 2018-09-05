#define FUSE_USE_VERSION 26

#include <fuse.h>
// #include <stdio.h>
// #include <string.h>
// #include <unistd.h>
// #include <fcntl.h>
// #include <dirent.h>
// #include <sys/time.h>
// #include <stdio.h>
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
// #include <stdlib.h>
#include <errno.h>
// #include <string.h>
// #include <signal.h>
// #include <sys/stat.h>
// #include <openssl/sha.h>
// #include <pthread.h>

#include "parse.h"
#include "ssyscalls.h"
#include "logger.h"

int num_servers;
int *sfds;
char **ips;
int *ports;

static int do_getattr5(const char *path, struct stat *stbuf);

void send_info_path_multiple(int *info, const char *path)
{
    int i;
    for (i = 0; i < num_servers; i++)
    {
        send_info_path(sfds[i], info, path);
    }
}

void send_path_multiple(const char *path)
{
    int i;
    for (i = 0; i < num_servers; i++)
    {
        send(sfds[i], path, strlen(path) + 1, MSG_NOSIGNAL);
    }
}

void get_rv_multiple(int *rv, bool b)
{
    int i;
    for (i = 0; i < num_servers; i++)
    {
        rv[i] = get_rv(sfds[i], b);
    }
}

int a_in_b(int a, int *b, int size)
{
    int i;
    for (i = 0; i < size; i++)
    {
        if (a == b[i])
            return i;
    }
    return -1;
}

int get_parity_index_in_stripe(int stripe)
{
    int t_stripe = stripe % num_servers;
    int last_idx = num_servers - 1;
    return last_idx - t_stripe;
}

int get_server_sfd_based_on_chunk(int chunk)
{
    int chunks_in_stripe = num_servers - 1;
    int stripe = chunk / chunks_in_stripe;
    int parity_idx = get_parity_index_in_stripe(stripe);
    int chunk_asynch_idx_in_stripe = chunk % chunks_in_stripe;
    int actul_idx = parity_idx + 1 + chunk_asynch_idx_in_stripe;
    int actul_idx_mod = actul_idx % num_servers;
    return sfds[actul_idx_mod];
}

int get_offset_of_stripe_based_on_chunk(int chunk)
{
    int chunks_in_stripe = num_servers - 1;
    int stripe = chunk / chunks_in_stripe;
    return stripe * CHUNK_SIZE;
}

void xor_array(char *dst, char *src, int size)
{
    int i;
    for (i = 0; i < size; i++)
    {
        dst[i] = dst[i] ^ src[i];
    }
}

#define PARITY_UPDATE -1

void update_stripe_parity(const char *path, int stripe, int index)
{
    char *parity = malloc(CHUNK_SIZE);
    char *buffer = malloc(CHUNK_SIZE);
    memset(parity, 0, CHUNK_SIZE);

    int info[INFO_SIZE] = {read_num, strlen(path) + 1, 0, 0, 0, 0}, i;
    send_info_path_multiple(info, path);

    int idx;
    if (index == PARITY_UPDATE)
        idx = get_parity_index_in_stripe(stripe);
    else
        idx = index;

    for (i = 0; i < num_servers; i++)
    {
        if (i == idx)
            continue;
        int todo[2] = {CHUNK_SIZE, stripe * CHUNK_SIZE}, actual_size;
        send(sfds[i], todo, sizeof(todo), MSG_NOSIGNAL);

        memset(buffer, 0, CHUNK_SIZE);
        read(sfds[i], &actual_size, sizeof(int));
        read(sfds[i], buffer, actual_size);

        todo[0] = 0;
        todo[1] = 0;
        send(sfds[i], todo, sizeof(todo), MSG_NOSIGNAL);

        xor_array(parity, buffer, CHUNK_SIZE);
    }

    int todo[2] = {0, 0};
    send(sfds[idx], todo, sizeof(todo), MSG_NOSIGNAL);

    info[0] = write_num;
    send_info_path_multiple(info, path);

    todo[0] = CHUNK_SIZE;
    todo[1] = stripe * CHUNK_SIZE;
    send(sfds[idx], todo, sizeof(todo), MSG_NOSIGNAL);
    send(sfds[idx], parity, CHUNK_SIZE, MSG_NOSIGNAL);

    todo[0] = 0;
    todo[1] = 0;
    send(sfds[idx], todo, sizeof(todo), MSG_NOSIGNAL);
}

void send_stop_multiple()
{
    int i;
    int todo[2] = {0, 0};
    for (i = 0; i < num_servers; i++)
    {
        send(sfds[i], todo, sizeof(todo), MSG_NOSIGNAL);
    }
}

void fill_server_with_other_servers(int id, const char *path)
{
    struct stat stbuf;
    do_getattr5(path, &stbuf);
    int i;
    for (i = 0; i < stbuf.st_size / (num_servers - 1); i++)
    {
        update_stripe_parity(path, i, id);
    }
}

static int do_open5(const char *path, struct fuse_file_info *fi)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {open_num, strlen(path) + 1, 0, 0, 0, 0};
    send_info_path_multiple(info, path);
    int rv[num_servers];
    get_rv_multiple(rv, false);

    int empty_server = a_in_b(-ENOENT, rv, num_servers);
    if (empty_server >= 0)
    {
        fill_server_with_other_servers(empty_server, path);
    }

    // pthread_mutex_unlock(&mutex);
    return 0;
}

static int do_read5(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {read_num, strlen(path) + 1, size, offset, 0, 0};
    send_info_path_multiple(info, path);

    int chunk_n = offset / CHUNK_SIZE;
    int local_offset = offset % CHUNK_SIZE;
    int local_size = CHUNK_SIZE - local_offset;
    local_size = min(size, local_size);
    int off = 0;

    while (size > 0)
    {
        int curr_sfd = get_server_sfd_based_on_chunk(chunk_n);
        int soff = get_offset_of_stripe_based_on_chunk(chunk_n);

        int todo[2] = {local_size, soff + local_offset}, actual_size;
        send(curr_sfd, todo, sizeof(todo), MSG_NOSIGNAL);

        read(curr_sfd, &actual_size, sizeof(int));
        read(curr_sfd, buf + off, actual_size);

        size -= local_size;
        off += local_size;
        chunk_n++;
        local_size = min(size, CHUNK_SIZE);
        local_offset = 0;
    }
    send_stop_multiple();

    // pthread_mutex_unlock(&mutex);

    return 0;
}

static int do_write5(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {write_num, strlen(path) + 1, size, offset, 0, 0};
    send_info_path_multiple(info, path);

    int chunk_n = offset / CHUNK_SIZE;
    int local_offset = offset % CHUNK_SIZE;
    int local_size = CHUNK_SIZE - local_offset;
    local_size = min(size, local_size);
    int off = 0, i;
    int start_stripe = chunk_n / (num_servers - 1);

    while (size > 0)
    {
        int curr_sfd = get_server_sfd_based_on_chunk(chunk_n);
        int soff = get_offset_of_stripe_based_on_chunk(chunk_n);
        int todo[2] = {local_size, soff + local_offset};
        send(curr_sfd, todo, sizeof(todo), MSG_NOSIGNAL);
        send(curr_sfd, buf + off, local_size, MSG_NOSIGNAL);
        size -= local_size;
        off += local_size;
        chunk_n++;
        local_size = min(size, CHUNK_SIZE);
        local_offset = 0;
    }
    send_stop_multiple();

    int end_stripe = chunk_n / (num_servers - 1);

    for (i = start_stripe; i < end_stripe; i++)
    {
        update_stripe_parity(path, i, PARITY_UPDATE);
    }

    // pthread_mutex_unlock(&mutex);

    return 0;
}

static int do_release5(const char *path, struct fuse_file_info *fi)
{
    return 0;
}

static int do_rename5(const char *from, const char *to)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {rename_num, strlen(from) + 1, strlen(to) + 1, 0, 0, 0};
    send_info_path_multiple(info, from);
    send_path_multiple(to);
    int rv[num_servers];
    get_rv_multiple(rv, true);
    // pthread_mutex_unlock(&mutex);
    return 0;
}

static int do_unlink5(const char *path)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {unlink_num, strlen(path) + 1, 0, 0, 0, 0};
    send_info_path_multiple(info, path);
    int rv[num_servers];
    get_rv_multiple(rv, true);
    // pthread_mutex_unlock(&mutex);
    return 0;
}

static int do_rmdir5(const char *path)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {rmdir_num, strlen(path) + 1, 0, 0, 0, 0};
    send_info_path_multiple(info, path);
    int rv[num_servers];
    get_rv_multiple(rv, true);
    // pthread_mutex_unlock(&mutex);
    return 0;
}

static int do_mkdir5(const char *path, mode_t mode)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {mkdir_num, strlen(path) + 1, mode, 0, 0, 0};
    send_info_path_multiple(info, path);
    int rv[num_servers];
    get_rv_multiple(rv, true);
    // pthread_mutex_unlock(&mutex);
    return 0;
}

static int do_readdir5(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {readdir_num, strlen(path) + 1, 0, 0, 0, 0};

    int sfd = sfds[0], nothing, read_ans;
    send(sfd, info, sizeof(int) * INFO_SIZE, MSG_NOSIGNAL);
    read_ans = read(sfd, &nothing, sizeof(nothing));

    if (read_ans <= 0)
    {
        sfd = sfds[1];
    }

    send_info_path(sfd, info, path);

    // char message[512];
    // snprintf(message, 512, "Read dirrctory %s", path);
    // log_msg(stor_name, primary_ip, primary_port, message);

    int rv[3];
    read(sfd, rv, sizeof(rv));

    while (rv[0] != 0)
    {
        if (rv[0] == -1)
        {
            errno = rv[1];
            // pthread_mutex_unlock(&mutex);
            return -errno;
        }
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = rv[0];
        st.st_mode = rv[1];
        char name[rv[2]];
        read(sfd, name, rv[2]);
        filler(buf, name, &st, 0);
        read(sfd, rv, sizeof(rv));
    }

    // pthread_mutex_unlock(&mutex);
    return 0;
}

static int do_getattr5(const char *path, struct stat *stbuf)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {getattr_num, strlen(path) + 1, 0, 0, 0, 0}, i;
    send_info_path_multiple(info, path);

    struct stat stats[num_servers];
    for (i = 0; i < num_servers; i++)
    {
        read(sfds[i], &stats[i], sizeof(struct stat));
    }

    off_t size = 0;
    for (i = 0; i < num_servers; i++)
    {
        size += stats[i].st_size;
    }
    stats[0].st_size = size;

    // blkcnt_t cnt = 0;
    // for (i = 0; i < num_servers; i++)
    // {
    // 	cnt += stats[i].st_blksize;
    // }
    // stats[0].st_blksize = cnt;

    memcpy(stbuf, &stats[0], sizeof(struct stat));

    int rv[num_servers];
    get_rv_multiple(rv, true);

    // char message[512];
    // snprintf(message, 512, "Get attribute %s", path);
    // log_msg(stor_name, primary_ip, primary_port, message);

    // pthread_mutex_unlock(&mutex);
    return rv[0];
}

static int do_mknod5(const char *path, mode_t mode, dev_t rdev)
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {mknod_num, strlen(path) + 1, mode, rdev, 0, 0};
    send_info_path_multiple(info, path);
    int rv[num_servers];
    get_rv_multiple(rv, true);
    // pthread_mutex_unlock(&mutex);
    return 0;
}

static int do_utimens5(const char *path, const struct timespec ts[2])
{
    // pthread_mutex_lock(&mutex);
    int info[INFO_SIZE] = {utimens_num, strlen(path) + 1, ts[0].tv_sec, ts[0].tv_nsec / 1000, ts[1].tv_sec, ts[1].tv_nsec / 1000};
    send_info_path_multiple(info, path);
    int rv[num_servers];
    get_rv_multiple(rv, true);
    // pthread_mutex_unlock(&mutex);
    return 0;
}

static int do_truncate5(const char *path, off_t size)
{
    // pthread_mutex_lock(&mutex);
    // int actul_size =
    int info[INFO_SIZE] = {truncate_num, strlen(path) + 1, size, 0, 0, 0};
    send_info_path_multiple(info, path);
    int rv[num_servers];
    get_rv_multiple(rv, true);
    // pthread_mutex_unlock(&mutex);
    return 0;
}

static struct fuse_operations do_oper5 = {
    .open = do_open5,
    .read = do_read5,
    .write = do_write5,
    .release = do_release5,
    .rename = do_rename5,
    .unlink = do_unlink5,
    .rmdir = do_rmdir5,
    .mkdir = do_mkdir5,
    .readdir = do_readdir5,
    .getattr = do_getattr5,
    .mknod = do_mknod5,
    .utimens = do_utimens5,
    .truncate = do_truncate5,
};

int mount_raid5(int argc, char *argv[], storage *stor)
{
    num_servers = stor->server_cnt;

    int i;
    sfds = malloc(sizeof(int) * num_servers);
    ips = malloc(sizeof(char *) * num_servers);
    ports = malloc(sizeof(int) * num_servers);
    for (i = 0; i < num_servers; i++)
    {
        ips[i] = stor->servers[i].ip;
        ports[i] = stor->servers[i].port;
        sfds[i] = get_connection(ips[i], ports[i]);
    }

    // pthread_t timer_thread;
    // pthread_create(&timer_thread, NULL, timer_function5, NULL);

    return fuse_main(argc, argv, &do_oper5, NULL);
}