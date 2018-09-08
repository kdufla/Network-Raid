#pragma once

#include "ssyscalls.h"

void write_in_cache(const char *path, int index, char *buffer);
bool read_from_cache(const char *path, int index, char *buffer, int off);
void remove_from_cache(const char *path, int index);
void cache_init(int size, cache_mode md);
