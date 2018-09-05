#pragma once

#include "parse.h"
#include "ssyscalls.h"
#include "logger.h"

int mount5(int argc, char *argv[], storage *stor, bool allow_log, int timeout, char *stor_name);