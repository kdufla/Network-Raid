#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

#include "parse.h"
#include "logger.h"

int log_fd;

void log_msg(char *stor_name, char *ip, int port, char *msg)
{
    int len = strlen(msg) + strlen(stor_name) + 100;
    char *buff = malloc(len);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    snprintf(buff, len, "[%d-%d-%d %d:%d:%d] %s %s:%d %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, stor_name, ip, port, msg);


    write(log_fd, buff, strlen(buff));
}

void init_logger(char *path)
{
    log_fd = open(path, O_CREAT | O_WRONLY, 0666);
}

// void main(int argc,char argv[])
// {
//     init_logger("loggerff");

//     log_msg("name", "127.0.0.1", 5000, "chemi tesli logeri mushaobs");
//     log_msg("name", "127.0.0.1", 5001, "tan dzaan magra");
// }