#include "filesys/inode.h"

#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

struct list open_inodes;
/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

block_sector_t get_sector_in_disk(struct inode* inode, block_sector_t block_in_file);
block_sector_t get_sector_in_disk1(struct inode* inode, block_sector_t block_in_file);
block_sector_t get_sector_in_disk2(block_sector_t sector, struct inode_disk* inode,
                                   block_sector_t block_in_file);
block_sector_t get_block_in_file(off_t offset);
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
/*static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {//这个需要改
  ASSERT(inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}*/

void check_inode() {
  struct list_elem* e;
  struct inode* inode = NULL;
  int i = 0;
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    i++;
    printf("the inode number %dhas sector %d is opened %d times\n", i, inode->sector,
           inode->open_cnt);
  }
}
/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {
  struct inode_disk* disk_inode = NULL;
  bool success = true;
  static char zeros[BLOCK_SECTOR_SIZE];
  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  disk_inode = calloc(1, sizeof *disk_inode); //该操作将结构体内的内存置0
  if (disk_inode != NULL) {
    free_map_allocate(1, &disk_inode->direct[0]);
    block_write(fs_device, disk_inode->direct[0], zeros);
    disk_inode->length = length;
    disk_inode->is_dir = is_dir;
    disk_inode->magic = INODE_MAGIC;
    block_sector_t end_s = bytes_to_sectors(length);
    for (int i = 0; i < end_s; i++) {
      get_sector_in_disk2(sector, disk_inode, i);
    }
    block_write(fs_device, sector, disk_inode);
    free(disk_inode);
  }
  return success;
}
int get_level(int sectors) {
  if (sectors < 0)
    return -1;
  if (sectors >= 0 && sectors < 12)
    return 0;
  if (sectors >= 12 && sectors < 140)
    return 1;
  if (sectors >= 140 && sectors < (140 + 16384))
    return 2;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      block_sector_t num_s = bytes_to_sectors(inode->data.length);
      for (int i = 0; i < num_s; i++) {
        block_sector_t sector1 = get_sector_in_disk(inode, i);
        free_map_release(sector1, 1);
      }
    }
    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;
  if (offset + size > inode->data.length)
    size = inode->data.length - offset;
  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = get_sector_in_disk1(inode, get_block_in_file(offset));
    if (sector_idx == -1) {
      printf("could not read at %d\n", offset);
      exit(-1);
    }
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
block_sector_t get_block_in_file(off_t offset) { return offset / BLOCK_SECTOR_SIZE; }
block_sector_t get_sector_in_disk(struct inode* inode, block_sector_t block_in_file) {
  static char zeros[BLOCK_SECTOR_SIZE];
  int b = block_in_file;
  int l = get_level(block_in_file);
  int ds = 0;
  switch (l) {
    case -1:
      break;
    case 0:
      if (inode->data.direct[b] == 0) {
        (free_map_allocate(1, &inode->data.direct[b]));
        block_write(fs_device, inode->sector, &inode->data);
        block_write(fs_device, inode->data.direct[b], zeros);
      }
      ds = inode->data.direct[b];
      break;

    case 1:
      struct indirect_block* ind = calloc(1, sizeof *ind);
      if (inode->data.indirect == 0) { //申请新的一级索引块
        (free_map_allocate(1, &inode->data.indirect));
        block_write(fs_device, inode->sector, &inode->data);
      } else
        block_read(fs_device, inode->data.indirect, ind);

      if (ind->block_entry[b - 12] == 0) { //申请新的数据块
        (free_map_allocate(1, &ind->block_entry[b - 12]));
        block_write(fs_device, inode->data.indirect, ind);
        block_write(fs_device, ind->block_entry[b - 12], zeros);
      }
      ds = ind->block_entry[b - 12];
      free(ind);
      break;

    case 2:
      struct indirect_block* ind2 = calloc(1, sizeof *ind2);
      struct indirect_block* ind1 = calloc(1, sizeof *ind1);
      if (inode->data.doubly_indirect == 0) {
        (free_map_allocate(1, &inode->data.doubly_indirect));
        block_write(fs_device, inode->sector, &inode->data);
      } else
        block_read(fs_device, inode->data.doubly_indirect, ind2);

      if (ind2->block_entry[(b - 12 - 128) / 128] == 0) {
        (free_map_allocate(1, &ind2->block_entry[(b - 12 - 128) / 128]));
        block_write(fs_device, inode->data.doubly_indirect, ind2);
      } else
        block_read(fs_device, ind2->block_entry[(b - 12 - 128) / 128], ind1);

      if (ind1->block_entry[(b - 12 - 128) % 128] == 0) { //申请新的数据块
        (free_map_allocate(1, &ind1->block_entry[(b - 12 - 128) % 128]));
        block_write(fs_device, ind2->block_entry[(b - 12 - 128) / 128], ind1);
        block_write(fs_device, ind1->block_entry[(b - 12 - 128) % 128], zeros);
      }
      ds = ind1->block_entry[(b - 12 - 128) % 128];
      free(ind2);
      free(ind1);
      break;
  }
  return ds;
}
block_sector_t get_sector_in_disk1(struct inode* inode, block_sector_t block_in_file) {
  static char zeros[BLOCK_SECTOR_SIZE];
  int b = block_in_file;
  int l = get_level(block_in_file);
  int ds = 0;
  switch (l) {
    case -1:
      break;
    case 0:
      if (inode->data.direct[b] == 0) {
        return -1;
      }
      ds = inode->data.direct[b];
      break;

    case 1:
      struct indirect_block* ind = calloc(1, sizeof *ind);
      if (inode->data.indirect == 0) { //申请新的一级索引块
        return -1;
      } else
        block_read(fs_device, inode->data.indirect, ind);

      if (ind->block_entry[b - 12] == 0) { //申请新的数据块
        return -1;
      }
      ds = ind->block_entry[b - 12];
      free(ind);
      break;

    case 2:
      struct indirect_block* ind2 = calloc(1, sizeof *ind2);
      struct indirect_block* ind1 = calloc(1, sizeof *ind1);
      if (inode->data.doubly_indirect == 0) {
        return -1;
      } else
        block_read(fs_device, inode->data.doubly_indirect, ind2);

      if (ind2->block_entry[(b - 12 - 128) / 128] == 0) {
        return -1;
      } else
        block_read(fs_device, ind2->block_entry[(b - 12 - 128) / 128], ind1);

      if (ind1->block_entry[(b - 12 - 128) % 128] == 0) { //申请新的数据块
        return -1;
      }
      ds = ind1->block_entry[(b - 12 - 128) % 128];
      free(ind2);
      free(ind1);

      break;
  }
  return ds;
}
block_sector_t get_sector_in_disk2(block_sector_t sector, struct inode_disk* disk_inode,
                                   block_sector_t block_in_file) {
  static char zeros[BLOCK_SECTOR_SIZE];
  int b = block_in_file;
  int l = get_level(block_in_file);
  int ds = 0;
  switch (l) {
    case -1:
      break;
    case 0:
      if (disk_inode->direct[b] == 0) {
        (free_map_allocate(1, &disk_inode->direct[b]));
        block_write(fs_device, sector, disk_inode);
        block_write(fs_device, disk_inode->direct[b], zeros);
      }
      ds = disk_inode->direct[b];
      break;

    case 1:
      struct indirect_block* ind = calloc(1, sizeof *ind);
      if (disk_inode->indirect == 0) { //申请新的一级索引块
        (free_map_allocate(1, &disk_inode->indirect));
        block_write(fs_device, sector, disk_inode);
      } else
        block_read(fs_device, disk_inode->indirect, ind);

      if (ind->block_entry[b - 12] == 0) { //申请新的数据块
        (free_map_allocate(1, &ind->block_entry[b - 12]));
        block_write(fs_device, disk_inode->indirect, ind);
        block_write(fs_device, ind->block_entry[b - 12], zeros);
      }
      ds = ind->block_entry[b - 12];
      free(ind);
      break;

    case 2:
      struct indirect_block* ind2 = calloc(1, sizeof *ind2);
      struct indirect_block* ind1 = calloc(1, sizeof *ind1);
      if (disk_inode->doubly_indirect == 0) {
        (free_map_allocate(1, &disk_inode->doubly_indirect));
        block_write(fs_device, sector, disk_inode);
      } else
        block_read(fs_device, disk_inode->doubly_indirect, ind2);

      if (ind2->block_entry[(b - 12 - 128) / 128] == 0) {
        (free_map_allocate(1, &ind2->block_entry[(b - 12 - 128) / 128]));
        block_write(fs_device, disk_inode->doubly_indirect, ind2);
      } else
        block_read(fs_device, ind2->block_entry[(b - 12 - 128) / 128], ind1);

      if (ind1->block_entry[(b - 12 - 128) % 128] == 0) { //申请新的数据块
        (free_map_allocate(1, &ind1->block_entry[(b - 12 - 128) % 128]));
        block_write(fs_device, ind2->block_entry[(b - 12 - 128) / 128], ind1);
        block_write(fs_device, ind1->block_entry[(b - 12 - 128) % 128], zeros);
      }
      ds = ind1->block_entry[(b - 12 - 128) % 128];
      free(ind2);
      free(ind1);
      break;
  }
  return ds;
}
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;
  int modified = 0;
  if (inode->deny_write_cnt)
    return 0;
  if (offset > inode->data.length) {
    block_sector_t begin_s = bytes_to_sectors(inode->data.length);
    block_sector_t end_s = bytes_to_sectors(offset);
    for (int i = begin_s; i < end_s; i++) {
      get_sector_in_disk(inode, i);
    }
  }
  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = get_sector_in_disk(inode, get_block_in_file(offset));
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    //off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    //int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < sector_left ? size : sector_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
    if (offset > inode->data.length) {
      inode->data.length = offset;
      modified = 1;
    }
  }
  free(bounce);
  if (modified)
    block_write(fs_device, inode->sector, &inode->data);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {

  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }
