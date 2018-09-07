#pragma once

int main_raid1(int argc, char *argv[], storage* stor);
int get_connection(char *ipstr, int port);
int send_info_path(int sfd, int *info, const char *path);
int get_rv(int sfd, bool return_zero);
