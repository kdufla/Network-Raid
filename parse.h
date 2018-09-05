#pragma once

typedef struct
{
	char *ip;
	int port;
} server;

typedef struct
{
	char *name;
	char *mountpoint;
	int raid;
	int server_cnt;
	server servers[10];
	server hotswap;
} storage;

void parse();
char *get_errorlog();
int get_cache_size();
char *get_cache_replacement();
int get_timeout();
storage *get_storage(int i);
int get_storage_cnt();