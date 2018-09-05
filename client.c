#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"
#include "ssyscalls.h"
#include "logger.h"
#include "raid5.h"
#include "raid1.h"

int main(int argc, char *argv[])
{
	bool allow_log;
	char *stor_name;
	int timeout;

	parse(argv[1]);
	init_logger(get_errorlog());
	storage *stor;
	allow_log = true;
	log_msg("none", "0.0.0.0", 0, "logger init");

	timeout = get_timeout();
	// umask(0);

	int i;
	for (i = 0; i < get_storage_cnt(); i++)
	{
		switch (fork())
		{
		case -1:
			exit(100);
		case 0:
			stor = get_storage(i);
			stor_name = strdup(stor->name);
			// mount_storage(stor);
			int argc = 5;
			char *argv[argc];
			argv[0] = strdup("net_raid_client");
			argv[1] = strdup(stor->mountpoint);
			argv[2] = strdup("-o");
			argv[3] = strdup("sync_read");
			argv[4] = strdup("-f");
			int save;
			if (stor->raid == 1)
			{
				save = mount1(argc, argv, stor, allow_log, timeout, stor_name);
			}

			if (stor->raid == 5)
			{
				// return mount5(argc, argv, stor, allow_log, timeout, stor_name);
			}
			return save;
		}
	}

	return 0;
}
