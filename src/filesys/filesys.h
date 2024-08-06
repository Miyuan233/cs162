#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */
#define NAME_MAX 14
/* Block device that contains the file system. */
struct file_info {
  bool is_dir;
  uintptr_t* fp;
};
extern struct block* fs_device;
extern struct lock filesys_lock;
void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(const char* name, off_t initial_size);
struct file_info* filesys_open(const char* name);
bool filesys_remove(const char* name);
struct inode* search_file(const char* file_name);
int get_next_part(char part[NAME_MAX + 1], const char** srcp);

#endif /* filesys/filesys.h */
