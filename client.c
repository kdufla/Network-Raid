#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"
#include "ssyscalls.h"
#include "logger.h"
#include "raid1.h"

int mount_storage(storage *stor)
{
	int argc = 5;
	char *argv[argc];
	argv[0] = strdup("net_raid_client");
	argv[1] = strdup(stor->mountpoint);
	argv[2] = strdup("-o");
	argv[3] = strdup("sync_read");
	argv[4] = strdup("-f");

	return main_raid1(argc, argv, stor);
}

int main(int argc, char *argv[])
{
	parse(argv[1]);
	init_logger(get_errorlog());
	storage *stor;
	log_msg("none", "0.0.0.0", 0, "logger init");


	int i;
	for (i = 0; i < get_storage_cnt(); i++)
	{
		switch (fork())
		{
		case -1:
			exit(100);
		case 0:
			stor = get_storage(i);
			mount_storage(stor);
		}
	}

	return 0;
}
