#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

struct priority_queue {
  struct thread* init_q[9];
  struct thread** prio_q;
  int capacity;
  int size;
  int tickets;
  int (*compare)(const void*, const void*);
};

int prio_q_init(struct priority_queue*, int (*compare)(const void*, const void*));
int parent(int i);
int left(int i);
int right(int i);
void swap(struct priority_queue* h, int i, int j);
void heapify(struct priority_queue*, int index);
struct thread* pop_heap(struct priority_queue*);
void heap_up(struct priority_queue*, int index);
void heap_down(struct priority_queue*, int index);
void heap_insert(struct priority_queue*, struct thread*);
void heap_resize(struct priority_queue*);
int max_prio_compare(const void* a, const void* b);
/* A counting semaphore. */
typedef struct semaphore {
  unsigned value;             /* Current value. */
  struct priority_queue heap; /* List of waiting threads. */
};

void sema_init(struct semaphore*, unsigned value);
void sema_down(struct semaphore*);
bool sema_try_down(struct semaphore*);
void sema_up(struct semaphore*);
void sema_self_test(void);

/* Lock. */
typedef struct lock {
  struct thread* holder;      /* Thread holding lock (for debugging). */
  struct semaphore semaphore; /* Binary semaphore controlling access. */
};

void lock_init(struct lock*);
void lock_acquire(struct lock*);
bool lock_try_acquire(struct lock*);
void lock_release(struct lock*);
bool lock_held_by_current_thread(const struct lock*);

/* Condition variable. */
struct condition {
  struct priority_queue cheap; /* List of waiting threads. */
};

void cond_init(struct condition*);
void cond_wait(struct condition*, struct lock*);
void cond_signal(struct condition*, struct lock*);
void cond_broadcast(struct condition*, struct lock*);

/* Readers-writers lock. */
#define RW_READER 1
#define RW_WRITER 0

struct rw_lock {
  struct lock lock;
  struct condition read, write;
  int AR, WR, AW, WW;
};

void rw_lock_init(struct rw_lock*);
void rw_lock_acquire(struct rw_lock*, bool reader);
void rw_lock_release(struct rw_lock*, bool reader);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile("" : : : "memory")

#endif /* threads/synch.h */
