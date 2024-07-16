#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

int write(int fd, const void* buffer, unsigned size);
int create(const char* file, unsigned initial_size);
#endif /* userprog/syscall.h */
