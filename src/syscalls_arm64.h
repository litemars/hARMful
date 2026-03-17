#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <sys/types.h>
#include <fcntl.h>

// ARM64 Linux syscall numbers
#define __NR_read           63
#define __NR_write          64
#define __NR_openat         56
#define __NR_close          57
#define __NR_lseek          62
#define __NR_mmap           222
#define __NR_munmap         215
#define __NR_mprotect       226
#define __NR_fstat          80
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426

#define QUEUE_DEPTH 32
#define IORING_OFF_SQ_RING 0x00000000ULL
#define IORING_OFF_CQ_RING 0x08000000ULL
#define IORING_OFF_SQES 0x10000000ULL

// Direct syscall wrapper for ARM64
static inline long direct_syscall6(long nr, long arg0, long arg1, 
                                   long arg2, long arg3, long arg4, long arg5) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = arg0;
    register long x1 __asm__("x1") = arg1;
    register long x2 __asm__("x2") = arg2;
    register long x3 __asm__("x3") = arg3;
    register long x4 __asm__("x4") = arg4;
    register long x5 __asm__("x5") = arg5;
    
    __asm__ volatile (
        "svc 0"
        : "=r"(x0)
        : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory"
    );
    return x0;
}

// Simplified syscall wrappers
#define io_uring_setup_direct( entries, params) \
    direct_syscall6(__NR_io_uring_setup, entries, (long)params, 0, 0, 0, 0)


#define io_uring_enter_direct( fd, to_submit,min_complete,flags) \
    direct_syscall6(__NR_io_uring_enter, fd, to_submit, min_complete, flags, 0, 0)


#define direct_openat(dirfd, path, flags, mode) \
    direct_syscall6(__NR_openat, dirfd, (long)path, flags, mode, 0, 0)

#define direct_read(fd, buf, count) \
    direct_syscall6(__NR_read, fd, (long)buf, count, 0, 0, 0)

#define direct_write(fd, buf, count) \
    direct_syscall6(__NR_write, fd, (long)buf, count, 0, 0, 0)

#define direct_close(fd) \
    direct_syscall6(__NR_close, fd, 0, 0, 0, 0, 0)

#define direct_lseek(fd, offset, whence) \
    direct_syscall6(__NR_lseek, fd, offset, whence, 0, 0, 0)

#define direct_mmap(addr, length, prot, flags, fd, offset) \
    direct_syscall6(__NR_mmap, (long)addr, length, prot, flags, fd, offset)

#define direct_munmap(addr, length) \
    direct_syscall6(__NR_munmap, (long)addr, length, 0, 0, 0, 0)

#endif // SYSCALLS_H
