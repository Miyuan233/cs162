#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127
#define MAX_FILE 128
typedef char lock_t;
typedef char sema_t;
/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct fd_node {
  int open;
  struct file* file;
};
struct fd_table {
  struct fd_node fd_node[MAX_FILE];
  int new_fd;
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  struct fd_table fd_table;

  struct list child_list;
  struct lock child_list_lock;
  struct child_node* child_node;

  int pthread_num;
  int next_upage;
  struct list pthread_list;

  struct list user_sema;
  struct list user_lock;
};

struct child_node {
  tid_t tid;
  struct semaphore load_sema;
  int load_success;
  volatile int exit_status;
  int waited;
  struct pcb* pcb;
  struct list_elem elem;
  struct semaphore sema_wait;
};

struct usema_node {
  struct list_elem elem;
  sema_t* usema;
  struct semaphore sema;
};
struct ulock_node {
  struct list_elem elem;
  sema_t* ulock;
  struct lock lock;
};

void userprog_init(void);

int process_practice(int i); //4.24
pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);
struct child_node* find_child(pid_t pid);
void* get_upage_addr(int next_upage);
#endif /* userprog/process.h */
