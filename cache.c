#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#include "cache.h"

typedef struct {
  char *path;
  int index;
  bool accessed;
  bool in_use;
} data;

int chunk_cnt;
char *cache;
data *cache_data;
cache_mode mode;

int get_free_idx(){
  int i;
  for (i = 0; i < chunk_cnt; i++) {
    if(cache_data[i].in_use == 0){
      return i;
    }
  }
  return -1;
}

int sc_evict(){
  int i;
  for (i = 0; i < chunk_cnt; i++) {
    if(cache_data[i].accessed == 0){
      free(cache_data[i].path);
      return i;
    }else{
      cache_data[i].accessed = 0;
    }
  }
  free(cache_data[0].path);
  return 0;
}

int lru_evict(){
  int i, min =INT_MAX, idx;
  for (i = 0; i < chunk_cnt; i++) {
    if(cache_data[i].accessed < min && cache_data[i].accessed > 0){
      min = cache_data[i].accessed;
      idx = i;
    }
  }
  free(cache_data[idx].path);
  return idx;
}

int mru_evict(){
  int i, max =0, idx;
  for (i = 0; i < chunk_cnt; i++) {
    if(cache_data[i].accessed > max && cache_data[i].accessed > 0){
      max = cache_data[i].accessed;
      idx = i;
    }
  }
  free(cache_data[idx].path);
  return idx;
}

void sc_write(const char *path, int index, char *buffer){
  int idx = get_free_idx();
  if(idx == -1){
    idx = sc_evict();
  }

  cache_data[idx].accessed = true;
  cache_data[idx].in_use = true;
  cache_data[idx].index = index;
  cache_data[idx].path = strdup(path);

  memcpy(cache+CHUNK_SIZE*idx, buffer, CHUNK_SIZE);
}

void ru_write(const char *path, int index, char *buffer){
  int idx = get_free_idx();
  if(idx == -1){
    if(mode == LRU)
      idx = lru_evict();
    else
      idx = mru_evict();
  }

  cache_data[idx].accessed = time(NULL);
  cache_data[idx].in_use = true;
  cache_data[idx].index = index;
  cache_data[idx].path = strdup(path);

  memcpy(cache+CHUNK_SIZE*idx, buffer, CHUNK_SIZE);
}

void write_in_cache(const char *path, int index, char *buffer) {
  if(mode == LRU || mode == MRU){
    ru_write(path, index, buffer);
  }else{
    sc_write(path, index, buffer);
  }
}

bool sc_read(const char *path, int index, char *buffer, int off){
  int i;
  for (i = 0; i < chunk_cnt; i++) {
    if(cache_data[i].index == index && cache_data[i].in_use){
      if(strcmp(cache_data[i].path, path) == 0){
        memcpy(buffer, cache + CHUNK_SIZE*i + off, CHUNK_SIZE - off);
        cache_data[i].accessed = true;
        return true;
      }
    }
  }
  return false;
}

bool ru_read(const char *path, int index, char *buffer, int off){
  int i;
  for (i = 0; i < chunk_cnt; i++) {
    if(cache_data[i].index == index && cache_data[i].in_use){
      if(strcmp(cache_data[i].path, path) == 0){
        memcpy(buffer, cache + CHUNK_SIZE*i + off, CHUNK_SIZE - off);
        cache_data[i].accessed = time(NULL);
        return true;
      }
    }
  }
  return false;
}

bool read_from_cache(const char *path, int index, char *buffer, int off){
  if(mode == LRU || mode == MRU){
    return ru_read(path, index, buffer, off);
  }else{
    return sc_read(path, index, buffer, off);
  }
}

void remove_from_cache(const char *path, int index){
  int i;
  for (i = 0; i < chunk_cnt; i++) {
    if(cache_data[i].index == index && cache_data[i].in_use){
      if(strcmp(cache_data[i].path, path) == 0){
        free(cache_data[i].path);
        cache_data[i].accessed = false;
        cache_data[i].in_use = false;
        return;
      }
    }
  }
}


void cache_init(int size, cache_mode md){
  mode = md;
  chunk_cnt = size / CHUNK_SIZE;
  cache = malloc(chunk_cnt * CHUNK_SIZE);
  cache_data = malloc(chunk_cnt * sizeof(data));
  memset(cache_data, 0, chunk_cnt * sizeof(data));
}
