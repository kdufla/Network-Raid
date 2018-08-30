#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"

int str_int(char *num)
{
	int len = strlen(num), i, dec = 0;
	for (i = 0; i < len; i++)
	{
		dec = dec * 10 + (num[i] - '0');
	}
	return dec;
}

char *errorlog;
int cache_size;
char *cache_replacement;
int timeout;
storage storages[10];

int storage_cnt;

void parse(char *file_name)
{
	FILE *file = fopen(file_name, "r");	 /* should check the result */
	char line[256];

	// error log
	fgets(line, sizeof(line), file);
	errorlog = malloc(256);
	char *start_ptr = strchr(line, '=');
	start_ptr += 2;
	char *end_ptr = strchr(line, '\n');
	*end_ptr = '\0';
	memcpy(errorlog, start_ptr, end_ptr - start_ptr);

	// cache size
	fgets(line, sizeof(line), file);
	start_ptr = strchr(line, '=');
	start_ptr += 2;
	end_ptr = strchr(line, '\n');
	*end_ptr = '\0';
	end_ptr--;
	int multiplier;
	switch (*end_ptr)
	{
	case 'K':
		multiplier = 1000;
		break;
	case 'M':
		multiplier = 1000000;
		break;
	case 'G':
		multiplier = 1000000000;
		break;

	default:
		multiplier = 1;
	}
	*end_ptr = '\0';
	cache_size = str_int(start_ptr) * multiplier;

	// cache replacement
	fgets(line, sizeof(line), file);
	cache_replacement = malloc(256);
	start_ptr = strchr(line, '=');
	start_ptr += 2;
	end_ptr = strchr(line, '\n');
	*end_ptr = '\0';
	memcpy(cache_replacement, start_ptr, end_ptr - start_ptr);

	// timeout
	fgets(line, sizeof(line), file);
	start_ptr = strchr(line, '=');
	start_ptr += 2;
	end_ptr = strchr(line, '\n');
	*end_ptr = '\0';
	timeout = str_int(start_ptr);

	storage_cnt = 0;

	while (fgets(line, sizeof(line), file))
	{
		// name
		fgets(line, sizeof(line), file);
		char *name = malloc(256);
		start_ptr = strchr(line, '=');
		start_ptr += 2;
		end_ptr = strchr(line, '\n');
		*end_ptr = '\0';
		memcpy(name, start_ptr, end_ptr - start_ptr);
		storages[storage_cnt].name = name;

		// mountpoint
		fgets(line, sizeof(line), file);
		char *mountpoint = malloc(256);
		start_ptr = strchr(line, '=');
		start_ptr += 2;
		end_ptr = strchr(line, '\n');
		*end_ptr = '\0';
		memcpy(mountpoint, start_ptr, end_ptr - start_ptr);
		storages[storage_cnt].mountpoint = mountpoint;

		// raid
		fgets(line, sizeof(line), file);
		start_ptr = strchr(line, '=');
		start_ptr += 2;
		end_ptr = strchr(line, '\n');
		*end_ptr = '\0';
		storages[storage_cnt].raid = str_int(start_ptr);

		// servers
		int curr_serv = 0;
		fgets(line, sizeof(line), file);
		start_ptr = strchr(line, '=');
		start_ptr += 2;
		end_ptr = strchr(line, ':');
		while (1)
		{
			*end_ptr = '\0';
			char *ip = malloc(16);
			strcpy(ip, start_ptr);
			storages[storage_cnt].servers[curr_serv].ip = ip;
			start_ptr = end_ptr + 1;
			end_ptr = strchr(start_ptr, ',');
			if (end_ptr == NULL)
			{
				end_ptr = strchr(start_ptr, '\n');
				*end_ptr = '\0';
				storages[storage_cnt].servers[curr_serv++].port = str_int(start_ptr);
				storages[storage_cnt].server_cnt = curr_serv;
				break;
			}

			*end_ptr = '\0';
			storages[storage_cnt].servers[curr_serv++].port = str_int(start_ptr);

			start_ptr = end_ptr + 2;
			end_ptr = strchr(start_ptr, ':');
		}

		// hotswap
		fgets(line, sizeof(line), file);
		start_ptr = strchr(line, '=');
		start_ptr += 2;
		end_ptr = strchr(line, ':');
		*end_ptr = '\0';
		char *ip = malloc(16);
		strcpy(ip, start_ptr);
		storages[storage_cnt].hotswap.ip = ip;
		start_ptr = end_ptr + 1;
		end_ptr = strchr(start_ptr, '\n');
		*end_ptr = '\0';
		storages[storage_cnt++].hotswap.port = str_int(start_ptr);
	}

	fclose(file);
}

char *get_errorlog()
{
	return errorlog;
}

int get_cache_size()
{
	return cache_size;
}

char *get_cache_replacement()
{
	return cache_replacement;
}

int get_timeout()
{
	return timeout;
}

storage *get_storage(int i)
{
	return storages + i;
}

int get_storage_cnt()
{
	return storage_cnt;
}
