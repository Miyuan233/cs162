#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"

#define BITMAP_ERROR SIZE_MAX

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);
struct lock filesys_lock;
/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();
  lock_init(&filesys_lock);
  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  bool find = 1;
  struct dir* dir1 = NULL;
  struct inode* inode = NULL;
  char name_part[NAME_MAX + 1];
  block_sector_t sector_of_the_pdir = 0;
  block_sector_t a = ROOT_DIR_SECTOR;

  if (name[0] != '/') {
    a = thread_current()->pcb->cur_dir;
    if (a == 0)
      a = ROOT_DIR_SECTOR;
  }

  inode = inode_open(a);

  while (find) {
    if (get_next_part(name_part, &name) == 0)
      break;
    dir1 = dir_open(inode);
    find = dir_lookup(dir1, name_part, &inode);
    sector_of_the_pdir = inode->sector;
    dir_close(dir1);
  }
  if (find || name[0] != '\0')
    return false;

  block_sector_t inode_sector = 0;
  struct dir* dir = dir_open(inode_open(sector_of_the_pdir));
  bool success =
      (dir != NULL && free_map_allocate(1, &inode_sector) &&
       inode_create(inode_sector, initial_size, 0) && dir_add(dir, name_part, inode_sector, 0));
  // printf("alloccate inode sector %d for file \n",inode_sector);
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file_info* filesys_open(const char* name) {
  bool find = 1;
  struct dir* dir1 = NULL;
  struct inode* inode = NULL;
  char name_part[NAME_MAX + 1];
  block_sector_t sector = 0;
  block_sector_t a = ROOT_DIR_SECTOR;

  if (name[0] != '/') {
    a = thread_current()->pcb->cur_dir;
    if (a == 0)
      a = ROOT_DIR_SECTOR;
  }

  inode = inode_open(a);

  while (find) {
    if (get_next_part(name_part, &name) == 0)
      break;
    dir1 = dir_open(inode);
    find = dir_lookup(dir1, name_part, &inode);
    dir_close(dir1);
  }
  if (!find)
    return NULL;

  struct file_info* p = calloc(1, sizeof(struct file_info));
  p->is_dir = inode->data.is_dir;
  if (p->is_dir)
    p->fp = (void*)dir_open(inode);
  else
    p->fp = (void*)file_open(inode);
  return p;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {

  bool success = dir_remove(name);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
struct inode* search_file(const char* file_name) {
  struct dir* dir1 = NULL;
  struct inode* inode = NULL;
  bool success = 1;
  bool relative = 0 ? 1 : (file_name[0] == '/');
  if (relative)
    inode = inode_open(thread_current()->pcb->cur_dir);
  else
    inode = inode_open(1);
  char* name = NULL;
  while (success) {
    if (get_next_part(name, &file_name) == 0)
      break;
    dir1 = dir_open(inode);
    success = dir_lookup(dir1, name, &inode);
    dir_close(dir1);
  }
  return inode;
}
/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}