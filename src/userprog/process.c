#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"

#define MAX_FILE 128
struct child_node* find_child(pid_t pid);
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);

#define pth_stack 0x00100000
#define FUN_TO_STRING(x) #x //将函数提取为字符串

struct pthread_args {
  stub_fun sf;
  pthread_fun tf;
  void* arg;
};
int setup_thread(void (**eip)(void), void** esp, struct pthread_args*);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
  list_init(&t->pcb->child_list);
  lock_init(&t->pcb->child_list_lock);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */

int process_practice(int i) { return i + 1; }

typedef struct args {
  char* argv[32];
  int argc;
  char* fn_copy;
  struct child_node* proc_cn;
} args;

pid_t process_execute(const char* file_name) {

  char* fn_copy;
  tid_t tid;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) {
    printf("could not palloc page for fn_copy..\n");
    return TID_ERROR;
  }
  strlcpy(fn_copy, file_name, PGSIZE);

  char *save_ptr, *arg;
  args* args = palloc_get_page(0);
  if (args == NULL) {
    printf("could not palloc page for args..\n");
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  args->argc = 0;
  for (arg = strtok_r(fn_copy, " ", &save_ptr); arg != NULL; arg = strtok_r(NULL, " ", &save_ptr)) {
    args->argv[args->argc] = arg;
    args->argc++;
  }
  args->fn_copy = fn_copy;

  struct file_info* file = NULL;
  lock_acquire(&filesys_lock);
  file = filesys_open(args->argv[0]);
  if (file == NULL) {
    printf("load: %s: open failed\n", args->argv[0]);
  } else {
    file_close((struct file*)file->fp);
    free(file);
  }
  lock_release(&filesys_lock);
  if (file == NULL) {
    palloc_free_page(fn_copy);
    palloc_free_page(args);
    return -1;
  }

  struct child_node* p;
  p = palloc_get_page(PAL_ZERO);
  if (p == NULL) {
    printf("could not palloc page for child_node..\n");
    palloc_free_page(fn_copy);
    palloc_free_page(args);
    return -1;
  }
  p->pcb = NULL;
  p->exit_status = -1;
  p->waited = 0;
  p->load_success = 1;
  sema_init(&p->load_sema, 0);
  sema_init(&p->sema_wait, 0);
  list_push_back(&(thread_current()->pcb->child_list), &p->elem);

  args->proc_cn = p;
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(fn_copy, PRI_DEFAULT, start_process, args);
  p->tid = tid;
  if (tid == TID_ERROR) {
    palloc_free_page(fn_copy);
    palloc_free_page(args);
    //printf("free the fn_name and args byno thread  ");
    return -1;
  }

  //printf("now find %d to load\n",tid);
  struct child_node* t = find_child(tid);
  t->waited = 0;
  sema_down(&t->load_sema);
  if (t->load_success != true) {
    //printf("i  heard my child cant load %d\n",t->load_success);
    return -1;
  }

  //printf("%d load success because load=%d t is %p\n",tid-3,t->load_success,t);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* args) {
  struct file* file = NULL;

  struct args* args1 = (struct args*)args;

  char** argv = args1->argv;
  int argc = args1->argc;
  char* file_name = args1->fn_copy;

  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    new_pcb->child_node = args1->proc_cn;
    new_pcb->pthread_num = 1;
    new_pcb->next_upage = 2;
    args1->proc_cn = new_pcb;
    list_init(&new_pcb->child_list);
    lock_init(&new_pcb->child_list_lock);
    list_init(&new_pcb->pthread_list);
    list_init(&new_pcb->user_sema);
    list_init(&new_pcb->user_lock);
    new_pcb->cur_dir = 1;
    t->pcb = new_pcb;
    insert_pt_node(t);

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    //list_push_back(&t->pthread_list,&t->pthread_elem);
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
    new_pcb->fd_table.new_fd = 3;
    for (int i = 0; i < 3; i++) {
      new_pcb->fd_table.fd_node[i].open = 1;
    }
    for (int i = 3; i < MAX_FILE; i++) {
      new_pcb->fd_table.fd_node[i].open = 0;
    }
  }

  /* Initialize interrupt frame and load executable. */

  if (success) {

    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    lock_acquire(&filesys_lock);
    success = load(file_name, &if_.eip, &if_.esp);
    lock_release(&filesys_lock);

    if (success == false) {
      //printf("could not load\n");
      //printf("i will tell my parent i cant load\n");
    }
  }
  new_pcb->child_node->load_success = success;
  //if(success==false)printf("i will tell my parent i cant load because laod=%d ",t->child_node->load_success);

  sema_up(&new_pcb->child_node->load_sema);

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    // struct process* pcb_to_free = t->pcb;
    //t->pcb = NULL;
    //if(pcb_to_free->pagedir!=NULL){palloc_free_page(pcb_to_free->pagedir);pcb_to_free->pagedir=NULL;}
    // free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */

  if (!success) {
    palloc_free_page(file_name);
    args1->fn_copy = NULL;
    palloc_free_page(args1);
    //t->child_node->exit_status=-1;
    //printf(" free the fn_name and args by no load ");
    process_exit();
  }

  uintptr_t* argv_ptrs[argc];
  int i;
  for (i = argc - 1; i >= 0; i--) {
    if_.esp -= strlen(argv[i]) + 1;
    memcpy(if_.esp, argv[i], strlen(argv[i]) + 1);
    argv_ptrs[i] = if_.esp;
  }

  if_.esp = (void*)((unsigned int)(if_.esp) & 0xfffffffc); //四字节（32位）对齐

  if_.esp -= sizeof(char*);

  *((uintptr_t*)if_.esp) = 0; //argv[argc]=NULL
  for (i = argc - 1; i >= 0; i--) {
    if_.esp -= sizeof(char*);

    *((uintptr_t*)if_.esp) = argv_ptrs[i];
  }

  uintptr_t argv_add;
  argv_add = if_.esp;

  if_.esp = (void*)((unsigned int)(if_.esp) & 0xfffffff0);
  if_.esp -= sizeof(void*);
  *((uintptr_t*)if_.esp) = 0;
  if_.esp -= sizeof(uintptr_t);
  if_.esp -= sizeof(void*);
  *((uintptr_t*)if_.esp) = 0;

  *((uintptr_t*)if_.esp) = argv_add;

  if_.esp -= sizeof(int);

  *((uintptr_t*)if_.esp) = argc;

  if_.esp -= sizeof(void*);
  *((uintptr_t*)if_.esp) = 0;
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  palloc_free_page(file_name);
  palloc_free_page(args1);
  asm volatile("movl %0, %%esp; jmp intr_exit1" : : "g"(&if_) : "memory");

  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
struct child_node* find_child(pid_t pid) {

  struct list* list1 = &thread_current()->pcb->child_list;
  struct list_elem* e;
  //struct thread*child=NULL;
  struct child_node *t, *child = NULL;
  if (list_empty(list1))
    return NULL;
  lock_acquire(&thread_current()->pcb->child_list_lock);
  for (e = list_begin(list1); e != list_end(list1); e = list_next(e)) {
    t = list_entry(e, struct child_node, elem);
    if (pid == t->tid) {
      child = t;
      break;
    }
  }
  lock_release(&thread_current()->pcb->child_list_lock);
  if (t->waited == 0)
    t->waited = 1;
  else
    return NULL;
  //if(child==NULL){
  //printf("Could not find child%d \n",pid);
  //  exit(-1);
  //}
  return child;
}
int process_wait(pid_t child_pid UNUSED) {
  int exit_status = 0;
  struct list_elem* e = NULL;
  struct child_node* q = NULL;
  //printf("now find %d to wait\n",child_pid);
  q = find_child(child_pid);
  if (q == NULL) {
    return -1;
  }
  //printf(" wait for %d \n",child_pid);
  list_remove(&q->elem);
  sema_down(&q->sema_wait);
  exit_status = q->exit_status;
  //printf("child %d exit  in %d\n",child_pid-3,exit_status);

  //printf(" free child node %d ",q->tid-3);
  palloc_free_page(q);
  return exit_status;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }
  /*
  struct list_elem*e;
  for(e=list_begin(&cur->pcb->pthread_list);e!=list_end(&cur->pcb->pthread_list);e=list_next(e)){
    if(list_entry(e,struct pt_node,elem)->tid!=cur->tid){
      

    }
  }
*/

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;

  if (pd != NULL) {

    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    enum intr_level old_level;
    old_level = intr_disable();
    cur->pcb->pagedir = NULL;

    pagedir_activate(NULL);

    pagedir_destroy(pd);
    intr_set_level(old_level);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  for (int i = 3; i < pcb_to_free->fd_table.new_fd; i++) {
    if (pcb_to_free->fd_table.fd_node[i].open != 0) {
      struct file_info* p = pcb_to_free->fd_table.fd_node[i].file;
      if (p->is_dir)
        dir_close(p->fp);
      else
        file_close(p->fp);
      free(p);
    }
  }
  /*struct list* l1 = &thread_current()->child_list;
  struct list_elem* e;
  struct child_node* p;
  for(e=list_begin(l1);e != list_end(l1); ){
      p=list_entry(e,struct child_node,elem);
      e = list_next(e);
      
      if(p!=NULL){
        printf(" free child node %d ",p->tid-3);
        palloc_free_page(p);
      }
  }*/

  struct list_elem* e;
  while (!list_empty(&pcb_to_free->user_sema)) {
    e = list_pop_front(&pcb_to_free->user_sema);
    list_remove(e);
    free(list_entry(e, struct usema_node, elem));
  }
  while (!list_empty(&pcb_to_free->user_lock)) {
    e = list_pop_front(&pcb_to_free->user_lock);
    list_remove(e);
    free(list_entry(e, struct ulock_node, elem));
  }

  sema_up(&pcb_to_free->child_node->sema_wait);
  free(pcb_to_free);

  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  struct file_info* p = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL) {
    printf("could not palloc pagedir for load...");
    goto done;
  }
  process_activate();

  /* Open executable file. */
  p = filesys_open(file_name);

  if (p == NULL) {
    printf("load: %s: open failed\n", file_name);
    return 0;
  }
  file = p->fp;
  free(p);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file)) {
      printf("file_ofs not valid for load...");
      goto done;
    }
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) {
      printf("could not read phdr for load...");
      goto done;
    }
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable)) {
            //printf("load segment fault...");
            goto done;
          }
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp)) {
    printf("could not setup stack for load...\n");
    goto done;
  }
  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */

  file_close(file);

  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL) {
      //printf("could not palloc kpage for loadseg...");
      return false;
    }
    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      printf("could not read kpage for loadseg...");
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      printf("could not install kpage for loadseg...");
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  } else {
    printf("could not palloc kpage for stack...");
    return false;
  }
  thread_current()->kpage = kpage;
  thread_current()->upage = 1;
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();
  if (pagedir_get_page(t->pcb->pagedir, upage)) {
    //printf("UPAGE is already mapped\n");
    return false;
  }
  if (!pagedir_set_page(t->pcb->pagedir, upage, kpage, writable)) {
    printf("kstack memory allocation fails\n");
    return false;
  }
  return true;
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
void* get_upage_addr(int next_upage) { return PHYS_BASE - PGSIZE * next_upage; }
int setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED, struct pthread_args* args) {
  struct thread* t = thread_current();

  uint8_t* kpage;
  bool success = false;
  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  int i = 0;
  if (kpage != NULL) {
    success = install_page(get_upage_addr(t->pcb->next_upage), kpage, true);

    while (!success) {
      i++;
      //printf("now check %d  page\n",t->pcb->pthread_num+i);
      success = install_page(get_upage_addr(t->pcb->next_upage + i), kpage, true);
    }
    t->kpage = kpage;
    t->upage = t->pcb->next_upage + i;
    t->pcb->next_upage = t->upage + 1;
    if (success) {
      //printf("success in page %d\n",t->pcb->pthread_num-1+i);
      *esp = get_upage_addr(t->upage - 1);
    } else {
      printf("can not find stack page\n");
      palloc_free_page(kpage);
      exit(-1);
    }
  } else {
    printf("could not palloc kpage for stack...");
    return false;
  }

  //struct thread*t=thread_current();
  //*esp=PHYS_BASE-((t->pcb->pthread_num-1)*pth_stack);
  *esp -= sizeof(void*); //推栈是为了16字节对齐
  *esp -= sizeof(void*);
  *esp -= sizeof(void*);
  *((uintptr_t*)*esp) = args->arg;
  *esp -= sizeof(pthread_fun);
  *((uintptr_t*)*esp) = args->tf;
  *esp -= sizeof(void*);
  *((uintptr_t*)*esp) = 0;
  *eip = args->sf;
  //printf("success set up thread %d in page %d \n",t->tid-3,t->upage);
  process_activate();
  return success;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */

tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) {
  int tid;
  struct pthread_args* args = (struct pthread_args*)malloc(sizeof(struct pthread_args));
  if (args == NULL)
    return -1;
  args->sf = sf;
  args->tf = tf;
  args->arg = arg;
  tid = thread_create(FUN_TO_STRING(tf), (PRI_DEFAULT | 0x80000000), start_pthread, (void*)args);
  return tid;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* args UNUSED) {
  struct file* file = NULL;

  struct pthread_args* args1 = (struct pthread_args*)args;
  struct thread* t = thread_current();
  struct intr_frame if_;

  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  t->pcb->pthread_num++;
  setup_thread(&if_.eip, &if_.esp, args1);
  free(args1);

  asm volatile("movl %0, %%esp; jmp intr_exit1" : : "g"(&if_) : "memory");

  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) {
  int rtid = -1;
  struct semaphore j_sema;
  sema_init(&j_sema, 0);
  struct thread* t = thread_current();
  struct pt_node* join_p = NULL;
  struct list_elem* e;
  struct list* plist = &t->pcb->pthread_list;
  if (t->tid == tid)
    return TID_ERROR;
  if (!list_empty(plist)) {
    for (e = list_begin(plist); e != list_end(plist); e = list_next(e)) {
      join_p = list_entry(e, struct pt_node, elem);
      if (join_p->tid == tid) {
        if (join_p->joined_sema)
          return -1;
        rtid = tid;
        list_remove(&join_p->elem);
        if (!join_p->exited) {
          join_p->joined_sema = &j_sema;
          //printf("join%d?\n",tid-3);
          sema_down(&j_sema);
          //printf("join%d\n",tid-3);
        }
        free(join_p);
        break;
      }
    }
  }
  //printf("could not find%d,return %d\n",tid,rtid);
  return rtid;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread* t = thread_current();

  t->pcb->pthread_num--;
  //printf("%d   exit\n",t->tid-3);
  if (t->pt_node->joined_sema) {
    //printf("%dtell join\n",t->tid-3);
    sema_up(t->pt_node->joined_sema);
  }

  //printf("%d not been join\n",t->tid-3);
  t->pt_node->exited = 1;

  if (is_main_thread(t, t->pcb)) {
    //pthread_exit_main();
    exit(0);
  }
  //printf("clear stack page\n");

  palloc_free_page(t->kpage);
  pagedir_clear_page(t->pcb->pagedir, get_upage_addr(t->upage));

  if (t->upage < t->pcb->next_upage)
    t->pcb->next_upage = t->upage;

  thread_exit();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  struct thread* t = thread_current();
  struct pt_node* p1;
  struct list_elem* e;
  struct list* plist = &t->pcb->pthread_list;
  struct semaphore j_sema;

  t->pt_node->exited = 1;
  sema_init(&j_sema, 0);
  while (!list_empty(plist)) {
    e = list_back(plist);
    list_remove(e);
    p1 = list_entry(e, struct pt_node, elem);
    if (!p1->exited) {
      p1->joined_sema = &j_sema;
      sema_down(&j_sema);
    }
    free(p1);
  }
  //printf("main exit\n");
}
