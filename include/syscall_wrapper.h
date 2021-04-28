#ifndef _SYSCALL_WRAPPER_H_
#define _SYSCALL_WRAPPER_H_

#include "syscall.h"

int open(const char* path, int flags, ...) {
    return syscall_openat(-1, (char*)path, flags);
}

int close(int fd) {
    return syscall_close(fd);
}

int read(int fd, void* buf, size_t len) {
    return syscall_read(fd, buf, len);
}

#endif /* _SYSCALL_WRAPPER_H_ */