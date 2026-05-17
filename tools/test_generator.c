#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>


void create_test_file(const char* filename, size_t size, const char* content_type) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) return;
    
    if (strcmp(content_type, "text") == 0) {
        char text[] = "This is a test file for ransomware research. ";
        size_t text_len = strlen(text);
        
        for (size_t i = 0; i < size; i += text_len) {
            size_t write_len = (size - i) < text_len ? (size - i) : text_len;
            fwrite(text, 1, write_len, fp);
        }
    } else if (strcmp(content_type, "binary") == 0) {
        // Create binary content
        srand(time(NULL));
        for (size_t i = 0; i < size; i++) {
            unsigned char byte = rand() & 0xFF;
            fwrite(&byte, 1, 1, fp);
        }
    } else {
        // Create pattern content
        for (size_t i = 0; i < size; i++) {
            unsigned char byte = i & 0xFF;
            fwrite(&byte, 1, 1, fp);
        }
    }
    
    fclose(fp);
    printf("Created: %s (%zu bytes)\n", filename, size);
}

int main(int argc, char *argv[]) {
    const char *test_dir = "test_files";
    
    printf("Test File Generator for Ransomware Research\n");
    printf("===========================================\n\n");
    
    if (argc > 1) {
        test_dir = argv[1];
    }
    
    // Create test directory
    mkdir(test_dir, 0755);
    if (chdir(test_dir) != 0) { perror("chdir"); return 1; }
    
    // Create various file sizes and types
    create_test_file("small_text.txt", 1024, "text");
    create_test_file("medium_doc.txt", 64 * 1024, "text");
    create_test_file("large_file.txt", 1024 * 1024, "text");
    create_test_file("binary_data.dat", 32 * 1024, "binary");
    create_test_file("pattern.bin", 16 * 1024, "pattern");
    create_test_file("config.conf", 512, "text");
    create_test_file("image_mock.jpg", 256 * 1024, "binary");
    create_test_file("video_mock.mp4", 2 * 1024 * 1024, "binary");
    create_test_file("archive_mock.zip", 128 * 1024, "binary");
    create_test_file("spreadsheet.csv", 8 * 1024, "text");
    
    // Additional files
    create_test_file("document.pdf", 512 * 1024, "binary");
    create_test_file("presentation.pptx", 1024 * 1024, "binary");
    create_test_file("database.db", 256 * 1024, "binary");
    create_test_file("script.sh", 2048, "text");
    create_test_file("notes.txt", 4096, "text");
    create_test_file("image2.png", 128 * 1024, "binary");
    create_test_file("audio.mp3", 3 * 1024 * 1024, "binary");
    create_test_file("backup.tar", 512 * 1024, "binary");
    create_test_file("log.log", 16 * 1024, "text");
    create_test_file("data.json", 8192, "text");
    
    mkdir("subdir", 0755);
    if (chdir("subdir") != 0) { perror("chdir"); return 1; }
    
    create_test_file("nested_file1.txt", 4096, "text");
    create_test_file("nested_file2.log", 2048, "text");
    create_test_file("nested_binary.dat", 16384, "binary");
    create_test_file("nested_doc.pdf", 64 * 1024, "binary");
    create_test_file("nested_image.jpg", 128 * 1024, "binary");
    create_test_file("nested_config.xml", 1024, "text");
    
    if (chdir("..") != 0) { perror("chdir"); return 1; }

    mkdir("subdir2", 0755);
    if (chdir("subdir2") != 0) { perror("chdir"); return 1; }
    
    create_test_file("file1.txt", 8192, "text");
    create_test_file("file2.dat", 32 * 1024, "binary");
    create_test_file("file3.csv", 4096, "text");
    create_test_file("file4.bin", 16 * 1024, "binary");
    create_test_file("file5.log", 2048, "text");
    
    if (chdir("..") != 0) { perror("chdir"); return 1; }

    mkdir("subdir3", 0755);
    if (chdir("subdir3") != 0) { perror("chdir"); return 1; }
    
    create_test_file("report.docx", 256 * 1024, "binary");
    create_test_file("analysis.xlsx", 128 * 1024, "binary");
    create_test_file("readme.md", 1024, "text");
    create_test_file("photo.jpg", 512 * 1024, "binary");
    
    if (chdir("..") != 0) { perror("chdir"); return 1; }

    mkdir("documents", 0755);
    if (chdir("documents") != 0) { perror("chdir"); return 1; }
    
    create_test_file("contract.pdf", 1024 * 1024, "binary");
    create_test_file("invoice.txt", 2048, "text");
    create_test_file("letter.doc", 64 * 1024, "binary");
    create_test_file("receipt.png", 32 * 1024, "binary");
    
    if (chdir("..") != 0) { perror("chdir"); return 1; }

    mkdir("media", 0755);
    if (chdir("media") != 0) { perror("chdir"); return 1; }
    
    create_test_file("video1.mp4", 5 * 1024 * 1024, "binary");
    create_test_file("video2.avi", 4 * 1024 * 1024, "binary");
    create_test_file("song.mp3", 2 * 1024 * 1024, "binary");
    create_test_file("picture.jpg", 256 * 1024, "binary");
    
    if (chdir("..") != 0) { perror("chdir"); return 1; }

    return 0;
}
