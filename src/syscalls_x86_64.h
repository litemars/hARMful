#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <sys/types.h>
#include <fcntl.h>

/* x86_64 Linux syscall numbers */
#define __NR_read 0
#define __NR_write 1
#define __NR_openat 257
#define __NR_close 3
#define __NR_lseek 8
#define __NR_mmap 9
#define __NR_munmap 11
#define __NR_mprotect 10
#define __NR_fstat 5
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426

#define QUEUE_DEPTH 32
#define IORING_OFF_SQ_RING 0x00000000ULL
#define IORING_OFF_CQ_RING 0x08000000ULL
#define IORING_OFF_SQES 0x10000000ULL

/* Direct syscall wrapper for x86_64 */
static inline long direct_syscall_6(long nr, long arg0, long arg1, long arg2,
                                     long arg3, long arg4, long arg5) {
    register long rax asm("rax") = nr;
    register long rdi asm("rdi") = arg0;
    register long rsi asm("rsi") = arg1;
    register long rdx asm("rdx") = arg2;
    register long r10 asm("r10") = arg3;
    register long r8 asm("r8") = arg4;
    register long r9 asm("r9") = arg5;

    asm volatile(
        "syscall"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );

    return rax;
}

/* Simplified syscall wrappers */
#define io_uring_setup_direct(entries, params) \
    direct_syscall_6(__NR_io_uring_setup, (entries), (long)(params), 0, 0, 0, 0)

#define io_uring_enter_direct(fd, to_submit, min_complete, flags) \
    direct_syscall_6(__NR_io_uring_enter, (fd), (to_submit), (min_complete), (flags), 0, 0)

#define direct_read(fd, buf, count) \
    direct_syscall_6(__NR_read, (fd), (long)(buf), (count), 0, 0, 0)

#define direct_write(fd, buf, count) \
    direct_syscall_6(__NR_write, (fd), (long)(buf), (count), 0, 0, 0)

#define direct_openat(dirfd, pathname, flags, mode) \
    direct_syscall_6(__NR_openat, (dirfd), (long)(pathname), (flags), (mode), 0, 0)

#define direct_close(fd) \
    direct_syscall_6(__NR_close, (fd), 0, 0, 0, 0, 0)

#define direct_lseek(fd, offset, whence) \
    direct_syscall_6(__NR_lseek, (fd), (offset), (whence), 0, 0, 0)

#define direct_mmap(addr, length, prot, flags, fd, offset) \
    (void*)direct_syscall_6(__NR_mmap, (long)(addr), (length), (prot), (flags), (fd), (offset))

#define direct_munmap(addr, length) \
    direct_syscall_6(__NR_munmap, (long)(addr), (length), 0, 0, 0, 0)

#define direct_mprotect(addr, len, prot) \
    direct_syscall_6(__NR_mprotect, (long)(addr), (len), (prot), 0, 0, 0)

#define direct_fstat(fd, statbuf) \
    direct_syscall_6(__NR_fstat, (fd), (long)(statbuf), 0, 0, 0, 0)

#endif /* SYSCALLS_H */
