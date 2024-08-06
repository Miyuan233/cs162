#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "lib/float.h"
#include "threads/malloc.h"
typedef char lock_t;
typedef char sema_t;

#define MAX_FILE 128
#define BITMAP_ERROR SIZE_MAX
static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  if (args >= 0xbffffffc) {
    printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
    process_exit();
  }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  //printf("System call number: %d\n", args[0]);
  switch (args[0]) {
    case SYS_EXIT:
      //printf("%s: exit(%d)\n",thread_current()->pcb->process_name, args[1]);
      //
      f->eax = args[1];
      exit(args[1]);
      break;

    case SYS_PRACTICE:
      //printf("%s: practice(%d)\n", thread_current()->pcb->process_name, args[1]);
      f->eax = process_practice(args[1]);
      //printf("%d",f->eax);
      break;

    case SYS_EXEC:
      //printf("%s: exec(%s)\n", thread_current()->pcb->process_name, args[1]);
      f->eax = exec((char*)args[1]);

      break;

    case SYS_WAIT:
      //printf("%s:wait(%d)\n", thread_current()->pcb->process_name,args[1]);
      f->eax = wait((pid_t)args[1]);
      break;

    case SYS_HALT:
      printf("%s: halt()\n", thread_current()->pcb->process_name);
      halt();
      break;

    case SYS_WRITE:
      f->eax = write((int)args[1], (const void*)args[2], (unsigned)args[3]);
      if (f->eax == -1) {
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        process_exit();
      }
      break;

    case SYS_CREATE:

      f->eax = (int)create((char*)args[1], (unsigned)args[2]);
      if (f->eax == -1) {
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        process_exit();
      }

      break;
    case SYS_REMOVE:

      f->eax = (int)remove((char*)args[1]);
      //if(f->eax==0){printf("%s: exit(-1)\n",thread_current()->pcb->process_name);process_exit(); }
      break;
    case SYS_OPEN:
      //printf("%s: open(%s)\n", thread_current()->pcb->process_name, args[1]);
      f->eax = open((char*)args[1]);
      //if(f->eax==-1){printf("%s: exit(-1)\n",thread_current()->pcb->process_name);process_exit(); }
      break;
    case SYS_FILESIZE:

      f->eax = filesize((int)args[1]);
      if (f->eax == -1) {
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        process_exit();
      }

      break;
    case SYS_CLOSE:
      if (args[1] <= 2 || args[1] >= MAX_FILE) {
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        process_exit();
      }
      close((int)args[1]);
      break;

    case SYS_READ:

      f->eax = read((int)args[1], (void*)args[2], (unsigned)args[3]);
      if (f->eax == -1) {
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        process_exit();
      }
      break;
    case SYS_TELL:

      f->eax = tell((int)args[1]);
      if (f->eax == -1) {
        printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
        process_exit();
      }
      break;
    case SYS_SEEK:
      f->eax = args[1];
      //printf("%s: write(%d)\n", thread_current()->pcb->process_name, args[1]);
      seek((int)args[1], (unsigned)args[2]);
      break;
    case SYS_COMPUTE_E:
      f->eax = sys_sum_to_e(args[1]);
      break;
    case SYS_PT_CREATE:
      f->eax = sys_pthread_create((stub_fun)args[1], (pthread_fun)args[2], (void*)args[3]);
      break;
    case SYS_PT_EXIT:
      sys_pthread_exit();
      break;
    case SYS_PT_JOIN:
      f->eax = sys_pthread_join((int)args[1]);
      break;
    case SYS_GET_TID:
      f->eax = get_tid();
      break;
    case SYS_SEMA_INIT:
      f->eax = usema_init((sema_t*)args[1], (int)args[2]);
      break;
    case SYS_SEMA_DOWN:
      f->eax = usema_down((sema_t*)args[1]);
      break;
    case SYS_SEMA_UP:
      f->eax = usema_up((sema_t*)args[1]);
      break;
    case SYS_LOCK_INIT:
      f->eax = ulock_init((lock_t*)args[1]);
      break;
    case SYS_LOCK_ACQUIRE:
      f->eax = ulock_acquire((lock_t*)args[1]);
      break;
    case SYS_LOCK_RELEASE:
      f->eax = ulock_release((lock_t*)args[1]);
      break;
    case SYS_CHDIR:
      f->eax = chdir((char*)args[1]);
      break;
    case SYS_MKDIR:
      f->eax = mkdir((char*)args[1]);
      break;
    case SYS_ISDIR:
      f->eax = isdir((int)args[1]);
      break;
    case SYS_INUMBER:
      f->eax = inumber((int)args[1]);
      break;
    case SYS_READDIR:
      f->eax = readdir((int)args[1], (char*)args[2]);
      break;

    defalut:
      printf("%s: no such syscall. exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
  }
}

/*Runs the executable whose name is given in cmd_line, passing any given arguments, 
    and returns the new process’s program id (pid). If the program cannot load or run 
    for any reason, return -1. Thus, the parent process cannot return from a call to exec
    until it knows whether the child process successfully loaded its executable. You 
    must use appropriate synchronization to ensure this.*/

pid_t exec(const char* cmd_line) {
  pid_t pid;
  pid = process_execute(cmd_line);
  if (pid == TID_ERROR) {
    return -1;
  }

  return pid;
}

/*A “fake” syscall designed to get you familiar with the syscall interface This
      syscall increments the passed in integer argument by 1 and returns it to the user.*/
int practice(int i) {
  check_inode();

  return (i + 1);
}

/*
    Terminates Pintos by calling the shutdown_power_off function in devices/shutdown.h.
    This should be seldom used, because you lose some information about possible deadlock
    situations, etc.*/
void halt(void) { shutdown_power_off(); }
/*
    Terminates the current user program, returning status to the kernel. If the process’s 
    parent waits for it (see below), this is the status that will be returned. 
    Conventionally, a status of 0 indicates success and nonzero values indicate errors. 
    Every user program that finishes in normally calls exit – even a program that returns 
    from main calls exit indirectly (see Program Startup). In order to make the test suite 
    pass, you need to print out the exit status of each user program when it exits. The 
    format should be %s: exit(%d) followed by a newline, where the process name and exit 
    code respectively subsitute %s and %d. You may need to modify the existing 
    implementation of exit to support other syscalls.*/
void exit(int status) {
  thread_current()->pcb->child_node->exit_status = status;

  thread_current()->pcb->main_thread = thread_current();
  pthread_exit_main();
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
}

int wait(pid_t pid) {
  int a;
  a = process_wait(pid);
  return a;
}

/*
    Creates a new file called file initially initial_size bytes in size. Returns true
    if successful, false otherwise. Creating a new file does not open it: opening the
    new file is a separate operation which would require an open system call.*/
int create(const char* file, unsigned initial_size) {
  if (file == NULL) {
    return -1;
  }
  bool a;
  if (file > 0xc0000000)
    return -1;
  a = filesys_create(file, (off_t)initial_size);
  //if(!a)printf("could not create %s\n",file);
  return a;
}

/*
    Deletes the file named file. Returns true if successful, false otherwise. A file
    may be removed regardless of whether it is open or closed, and removing an open
    file does not close it. See this section of the FAQ for more details.*/
int remove(const char* file) {
  //lock_acquire(&filesys_lock);
  //printf("remove %s \n",file);
  if (file == NULL || (uint8_t*)file > (uint8_t*)0xc0000000) {
    return 0;
  }
  bool a;
  a = filesys_remove(file);
  //lock_release(&filesys_lock);
  return a;
}
/*
    Opens the file named file. Returns a nonnegative integer handle called a “file 
    descriptor” (fd), or -1 if the file could not be opened.

    File descriptors numbered 0 and 1 are reserved for the console: 0 (STDIN_FILENO) 
    is standard input and 1 (STDOUT_FILENO) is standard output. open should never 
    return either of these file descriptors, which are valid as system call arguments 
    only as explicitly described below.

    Each process has an independent set of file descriptors. File descriptors in 
    Pintos are not inherited by child processes.

    When a single file is opened more than once, whether by a single process or 
    different processes, each open returns a new file descriptor. Different file 
    descriptors for a single file are closed independently in separate calls to close 
    and they do not share a file position.*/

int open(const char* file) {
  lock_acquire(&filesys_lock);
  int fd, new_fd, running = 0;
  struct file_info* f;
  struct list_elem* e = NULL;
  struct thread *t = thread_current(), *t1;
  if (file == NULL || (strlen(file) == 0) || (uint8_t*)file >= (uint8_t*)0xc0000000) {
    lock_release(&filesys_lock);
    return -1;
  }
  if ((f = filesys_open(file)) == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    t1 = list_entry(e, struct thread, allelem);
    if (strcmp(file, t1->name) == 0) {
      running = 1;
      break;
    }
  }
  if (running)
    file_deny_write(f->fp);

  fd = t->pcb->fd_table.new_fd;
  t->pcb->fd_table.fd_node[fd].open = 1;
  t->pcb->fd_table.fd_node[fd].file = f;
  new_fd = fd;
  while (t->pcb->fd_table.fd_node[new_fd].open == 1 && new_fd < MAX_FILE) {
    new_fd++;
  }
  t->pcb->fd_table.new_fd = new_fd;
  lock_release(&filesys_lock);
  //printf("now we open %d\n",fd);
  return fd;
}

/*
    Returns the size, in bytes, of the open file with file descriptor fd. Returns -1 if 
    fd does not correspond to an entry in the file descriptor table.*/
int filesize(int fd) {
  int length = 0;
  struct inode* inode;
  struct file_info* p;
  struct thread* t = thread_current();
  p = t->pcb->fd_table.fd_node[fd].file;
  if (t->pcb->fd_table.fd_node[fd].open == 0 || p == NULL)
    return -1;
  if (p->is_dir) {
    struct dir* d = p->fp;
    length = d->inode->data.length;
  } else {
    struct file* f = p->fp;
    length = f->inode->data.length;
  }

  return length;
}

/*Closes file descriptor fd. Exiting or terminating a process must implicitly 
    close all its open file descriptors, as if by calling this function for each one. 
    If the operation is unsuccessful, it can either exit with -1 or it can just fail 
    silently.*/
void close(int fd) {
  lock_acquire(&filesys_lock);
  struct thread* t = thread_current();
  if (t->pcb->fd_table.fd_node[fd].open == 0) {
    lock_release(&filesys_lock);
    exit(-1);
  }
  t->pcb->fd_table.fd_node[fd].open = 0;
  struct file_info* p = t->pcb->fd_table.fd_node[fd].file;
  if (p->is_dir)
    dir_close(p->fp);
  else
    file_close(p->fp);
  free(p);
  //printf("now we close %d\n",fd);
  if (fd < t->pcb->fd_table.new_fd)
    t->pcb->fd_table.new_fd = fd;
  lock_release(&filesys_lock);
}

/*
    Reads size bytes from the file open as fd into buffer. Returns the number of bytes 
    actually read (0 at end of file), or -1 if the file could not be read (due to a 
    condition other than end of file, such as fd not corresponding to an entry in the 
    file descriptor table). STDIN_FILENO reads from the keyboard using the input_getc 
    function in devices/input.c.*/
int read(int fd, void* buffer, unsigned size) {
  int read1;
  struct file_info* p;
  struct thread* t = thread_current();
  //printf("now we read%d\n",fd);

  if (size == 0)
    return 0;
  if (fd < 0 || fd >= MAX_FILE || buffer == NULL || buffer >= 0xc0000000) {
    //printf("wrong input\n");没有处理stdin
    return -1;
  }
  p = t->pcb->fd_table.fd_node[fd].file;

  if (t->pcb->fd_table.fd_node[fd].open == 0 || p == NULL || p->is_dir) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  read1 = file_read(p->fp, buffer, size);
  lock_release(&filesys_lock);
  //if(read1==-1)printf("rerror read\n");
  //printf("read= %d\n",read1);
  return read1;
}
int write(int fd, const void* buffer, unsigned size) {

  int a = size;
  if (fd == 1) {
    char* s = (char*)buffer;
    putbuf(buffer, size);
    if (strlen(s) < size)
      a = strlen(s);
  } else {

    struct file_info* p;
    struct thread* t = thread_current();
    if (size == 0)
      return 0;
    if (size < 0 || fd >= MAX_FILE || buffer >= 0xc0000000) {

      return -1;
    }

    p = t->pcb->fd_table.fd_node[fd].file;

    if (t->pcb->fd_table.fd_node[fd].open == 0 || p == NULL || p->is_dir) {
      return -1;
    }

    lock_acquire(&filesys_lock);
    a = file_write(p->fp, buffer, size);
    lock_release(&filesys_lock);
  }
  //if(a!=size)printf("could not write\n");
  return a;
}
/*Returns the position of the next byte to be read or written in open file fd, 
    expressed in bytes from the beginning of the file. If the operation is unsuccessful, 
    it can either exit with -1 or it can just fail silently.*/
int tell(int fd) {
  int tell1;
  struct file_info* p;
  struct thread* t = thread_current();
  if (fd < 0 || fd >= MAX_FILE) {
    return -1;
  }
  p = t->pcb->fd_table.fd_node[fd].file;
  if (t->pcb->fd_table.fd_node[fd].open == 0) {
    printf(" file did not open\n");
    return -1;
  }
  tell1 = file_tell(p->fp);
  return tell1;
}

/*
    Changes the next byte to be read or written in open file fd to position, 
    expressed in bytes from the beginning of the file. Thus, a position of 0 
    is the file’s start. If fd does not correspond to an entry in the file 
    descriptor table, this function should do nothing.

    A seek past the current end of a file is not an error. A later read obtains 
    0 bytes, indicating end of file. A later write extends the file, filling any 
    unwritten gap with zeros. However, in Pintos files have a fixed length until 
    Project File Systems is complete, so writes past end-of-file will return an 
    error. These semantics are implemented in the file system and do not require 
    any special effort in the syscall implementation.*/
void seek(int fd, unsigned position) {

  struct file_info* p;
  struct thread* t = thread_current();
  if (fd < 0 || fd >= MAX_FILE || position < 0) {
    return;
  }
  p = t->pcb->fd_table.fd_node[fd].file;
  if (t->pcb->fd_table.fd_node[fd].open == 0) {
    printf(" file did not open\n");
    return;
  }

  file_seek(p->fp, position);
}
/*
    This is similar to the practice syscall in that it’s a “fake” system 
    call that doesn’t exist in any modern OS. This system call computes an 
    approximation of ???using the Taylor series for the constant e. Most 
    of the mathematical logic for implementing this system call has been 
    done for you in sys_sum_to_e in lib/float.c. Once you validate the argument 
    int n from the system call, you can simply store the result of sys_sum_to_e 
    in the eax register for return. This system call is not intended to be 
    difficult to implement correctly.*/
double compute_e(int n) {
  double e = sum_to_e(n);
  return e;
}

/*
      Creates a new user thread running stub function sfun, with 
      arguments tfun and arg. Returns TID of created thread, or 
      TID_ERROR if allocation failed.*/
tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg) {
  tid_t tid = pthread_execute(sfun, tfun, arg);
  return tid;
}

/*
      Terminates the calling user thread. If the main thread calls 
      pthread_exit, it should join on all currently active threads, 
      and then exit the process.*/
void sys_pthread_exit(void) { pthread_exit(); }

/*  Suspends the calling thread until the thread with TID tid 
      finishes. Returns the TID of the thread waited on, or TID_ERROR 
      if the thread could not be joined on. It is only valid to join 
      on threads that are part of the same process and have not yet 
      been joined on. It is valid to join on a thread that was part 
      of the same process, but has already terminated – in such cases, 
      the sys_pthread_join call should not block. Any thread can join 
      on any other thread (the main thread included). If a thread joins 
      on main, it should be woken up and allowed to run after main 
      calls pthread_exit but before the process is killed (see above).
      The defintions of tid_t, stub_fun, and pthread_fun in the kernel 
      are in userprog/process.h.*/
tid_t sys_pthread_join(tid_t tid) { return pthread_join(tid); }

/*
      Initializes lock, where lock is a pointer to a lock_t in userspace. 
      Returns true if initialization was successful. You do not have to 
      handle the case where lock_init is called on the same argument twice; 
      you can assume that the result of doing so is undefined behavior.
      */
int ulock_init(lock_t* lock) {
  if (lock == NULL)
    return 0;
  struct ulock_node* p = (struct usema_lock*)malloc(sizeof(struct ulock_node));
  if (!p)
    return 0;
  lock_init(&p->lock);
  p->ulock = lock;
  list_push_front(&thread_current()->pcb->user_lock, &p->elem);
  return 1;
}

/*
      Acquires lock, blocking if necessary, where lock is a pointer to 
      a lock_t in userspace. Returns true if the lock was successfully 
      acquired, false if the lock was not registered with the kernel in 
      a lock_init call or if the current thread already holds the lock.
      */
struct ulock_node* find_ulock(lock_t* lock) {
  struct list* l1 = &thread_current()->pcb->user_lock;
  struct list_elem* e;
  struct ulock_node *u = NULL, *u1;
  if (list_empty(l1))
    return NULL;
  for (e = list_begin(l1); e != list_end(l1); e = list_next(e)) {
    u1 = list_entry(e, struct ulock_node, elem);
    if (u1->ulock == lock) {
      u = u1;
      break;
    }
  }
  return u;
}

int ulock_acquire(lock_t* lock) {
  if (lock == NULL)
    return false;
  struct ulock_node* u = find_ulock(lock);
  if (!u)
    return false;
  lock_acquire(&u->lock);
  return true;
}

/*    Releases lock, where lock is a pointer to a lock_t in userspace.
      Returns true if the lock was successfully released, false if the lock
      was not registered with the kernel in a lock_init call or if the current 
      thread does not hold the lock.*/
int ulock_release(lock_t* lock) {
  if (lock == NULL)
    return false;
  struct ulock_node* u = find_ulock(lock);
  if (!u)
    return false;
  lock_release(&u->lock);
  return true;
}

/*    
      Initializes sema to val, where sema is a pointer to a sema_t 
      in userspace. Returns true if initialization was successful. 
      You do not have to handle the case where sema_init is called 
      on the same argument twice; you can assume that the result of 
      doing so is undefined behavior.*/
int usema_init(sema_t* sema, int val) {

  if (sema == NULL || val < 0)
    return 0;
  struct usema_node* p = (struct usema_node*)malloc(sizeof(struct usema_node));
  if (!p)
    return 0;
  sema_init(&p->sema, val);
  p->usema = sema;
  list_push_front(&thread_current()->pcb->user_sema, &p->elem);
  return 1;
}

/*Downs sema, blocking if necessary, where sema is a pointer to a 
      sema_t in userspace. Returns true if the semaphore was successfully 
      downed, false if the semaphore was not registered with the kernel 
      in a sema_init call.
          */
struct usema_node* find_usema(sema_t* sema) {
  struct list* l1 = &thread_current()->pcb->user_sema;
  struct list_elem* e;
  struct usema_node *u = NULL, *u1;
  if (list_empty(l1))
    return NULL;
  for (e = list_begin(l1); e != list_end(l1); e = list_next(e)) {
    u1 = list_entry(e, struct usema_node, elem);
    if (u1->usema == sema) {
      u = u1;
      break;
    }
  }
  return u;
}

int usema_down(sema_t* sema) {
  if (sema == NULL)
    return false;
  struct usema_node* u = find_usema(sema);
  if (!u)
    return false;
  sema_down(&u->sema);
  return true;
}

/*Ups sema, where sema is a pointer to a sema_t in userspace. Returns true
      if the sema was successfully upped, false if the sema was not registered 
      with the kernel in a sema_init call.
      Your task will be to implement these system calls in the kernel. On every 
      synchronization system call, you are allowed to make a kernel crossing. 
      In other words, you do not need to avoid kernel crossings like is done in 
      the implementation of futex.
      Given user-level locks and semaphores, it’s possible to implement user-level 
      condition variables entirely at user-level with locks and semaphores as primitives. 
      Feel free to implement condition variables if you would like, but it is not 
      required as part of the project. The implementation will look similar to 
      the implementation of CVs in threads/synch.c.
      */
int usema_up(sema_t* sema) {
  if (sema == NULL)
    return false;
  struct usema_node* u = find_usema(sema);
  if (!u)
    return false;
  sema_up(&u->sema);
  return true;
}

tid_t get_tid(void) { return thread_tid(); }

/*
Changes the current working directory of the process to dir, 
which may be relative or absolute. Returns true if successful, 
false on failure.*/

int chdir(const char* dir) {
  //printf("change to  %s\n", dir);
  bool success = 1;
  struct dir* dir1 = NULL;
  struct inode* inode = NULL;
  char name[NAME_MAX + 1];
  block_sector_t a = ROOT_DIR_SECTOR;

  if (dir[0] != '/') {
    a = thread_current()->pcb->cur_dir;
    if (a == 0)
      a = ROOT_DIR_SECTOR;
  }

  inode = inode_open(a);

  while (success) {
    if (get_next_part(name, &dir) == 0)
      break;
    dir1 = dir_open(inode);
    success = dir_lookup(dir1, name, &inode);
    dir_close(dir1);
  }
  if (success) {
    thread_current()->pcb->cur_dir = inode->sector;
    inode_close(inode);
  }
  //else{printf("coule not change to %s\n", name);}
  return success;
}

/*
Creates the directory named dir, which may be relative or absolute. 
Returns true if successful, false on failure. Fails if dir already 
exists or if any directory name in dir, besides the last, does not 
already exist. That is, mkdir("/a/b/c") succeeds only if /a/b already 
exists and /a/b/c does not.*/
int mkdir(const char* name) {
  //printf(" create dir%s \n",name);
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

  /*创建目录并将目录项添加到父目录*/
  block_sector_t inode_sector = 0;

  free_map_allocate(1, &inode_sector);
  if (!inode_sector)
    return false;
  if (!inode_create(inode_sector, 0, 1)) {
    free_map_release(inode_sector, 1);
    return false;
  }

  struct dir* pdir = dir_open(inode_open(sector_of_the_pdir));
  dir_add(pdir, name_part, inode_sector, 1);
  dir_close(pdir);

  /*初始化自身目录项*/
  struct dir* cdir = dir_open(inode_open(inode_sector));
  dir_add(cdir, ".", inode_sector, 1);
  dir_add(cdir, "..", sector_of_the_pdir, 1);
  dir_close(cdir);

  return true;
}
/*

Reads a directory entry from file descriptor fd, which must represent 
a directory. If successful, stores the null-terminated file name in 
name, which must have room for READDIR_MAX_LEN + 1 bytes, and returns 
true. If no entries are left in the directory, returns false.
. and .. should not be returned by readdir
If the directory changes while it is open, then it is acceptable 
for some entries not to be read at all or to be read multiple times. 
Otherwise, each directory entry should be read once, in any order.
READDIR_MAX_LEN is defined in lib/user/syscall.h. If your file 
system supports longer file names than the basic file system, you 
should increase this value from the default of 14.*/
int readdir(int fd, char* name) {
  if (!isdir(fd))
    return false;
  struct dir* dir1 = thread_current()->pcb->fd_table.fd_node[fd].file->fp;
  if (!dir1)
    return false;
  return dir_readdir(dir1, name);
}

/*
Returns true if fd represents a directory, false if it represents an ordinary file.*/
int isdir(int fd) { return thread_current()->pcb->fd_table.fd_node[fd].file->is_dir; }

/*
Returns the inode number of the inode associated with fd, which
 may represent an ordinary file or a directory.
An inode number persistently identifies a file or directory. It 
is unique during the file’s existence. In Pintos, the sector 
number of the inode is suitable for use as an inode number.

We have provided the ls and mkdir user programs, which are 
straightforward once the above syscalls are implemented. 
We have also provided pwd, which is not so straightforward. 
The shell program implements cd internally.

The pintos extract and pintos append commands should now accept 
full path names, assuming that the directories used in the paths 
have already been created. This should not require any significant 
extra effort on your part.

*/
int inumber(int fd) {
  void* p = thread_current()->pcb->fd_table.fd_node[fd].file->fp;
  if (isdir(fd)) {
    struct dir* d = p;
    return d->inode->sector;
  } else {
    struct file* f = p;
    return f->inode->sector;
  }
}