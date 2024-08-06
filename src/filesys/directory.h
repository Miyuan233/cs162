#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

struct inode;
/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  int32_t pos;         /* Current position. */
  char name[NAME_MAX + 1];
};

/* A single directory entry. （32 Bytes）*/
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
  bool is_dir;                 /* 1: is dir;  0: is file */
  bool unused[11];
};
/* Opening and closing directories. */
bool dir_create(block_sector_t sector, size_t entry_cnt);
struct dir* dir_open(struct inode*);
struct dir* dir_open_root(void);
struct dir* dir_reopen(struct dir*);
void dir_close(struct dir*);
struct inode* dir_get_inode(struct dir*);

struct dir* get_cur_dir();
struct dir* get_parent_dir();

/* Reading and writing. */
bool dir_lookup(const struct dir*, const char* name, struct inode**);
bool dir_add(struct dir*, const char* name, block_sector_t, bool);
bool dir_remove(const char* name);
bool dir_readdir(struct dir*, char name[NAME_MAX + 1]);
bool dir_empty(struct dir*);

#endif /* filesys/directory.h */
