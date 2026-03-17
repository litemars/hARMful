#!/bin/bash

set -e

# Color codes for visual output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Test configuration
readonly TEST_FILE="./test_files/large_file.txt"
readonly TEST_DIR="./test_files"
readonly METHODS=(1 2 3 4 5 6)
readonly METHOD_NAMES=("Direct SysCall encryption" "io_uring encryption" "Partial file encryption" "Page encryption" "io_uring Direct SysCall encryption" "io_uring Partial encryption")

# Statistics
TESTS_PASSED=0
TESTS_FAILED=0
START_TIME=$(date +%s)

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helper Functions
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_header() {
    echo -e "${BOLD}${MAGENTA}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                  hARMful                                   ║"
    echo "║         Encryption/Decryption Validation (ARM64)           ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BOLD}${CYAN}▶ $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_progress() {
    local current=$1
    local total=$2
    local method_name=$3
    local percent=$((current * 100 / total))
    
    echo -ne "\r${CYAN}[${NC}"
    printf "%-50s" $(printf '#%.0s' $(seq 1 $((percent / 2))))
    echo -ne "${CYAN}]${NC} ${percent}% - Testing ${method_name}..."
}

print_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    echo -e "\n${BOLD}${MAGENTA}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                     Test Summary                           ║"
    echo "╠════════════════════════════════════════════════════════════╣"
    printf "║  ${GREEN}Passed:${NC} %-4d                                           ║\n" "$TESTS_PASSED"
    printf "║  ${RED}Failed:${NC} %-4d                                           ║\n" "$TESTS_FAILED"
    printf "║  Duration: %-3ds                                         ║\n" "$duration"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}${BOLD}🎉 All tests passed successfully!${NC}\n"
        return 0
    else
        echo -e "${RED}${BOLD}❌ Some tests failed. Please review the output above.${NC}\n"
        return 1
    fi
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Validation Functions
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

check_architecture() {
    print_section "System Check"
    
    if [[ $(uname -m) != "aarch64" ]]; then
        print_error "This test must run on ARM64/aarch64 architecture"
        print_info "Current architecture: $(uname -m)"
        exit 1
    fi
    
    print_success "Running on ARM64 architecture"
    print_info "Kernel: $(uname -r)"
    print_info "OS: $(uname -o)"
}

build_tools() {
    print_section "Building Tools"
    
    if make clean && make all; then
        print_success "Build completed successfully"
    else
        print_error "Build failed"
        exit 1
    fi
}

verify_file_state() {
    local file=$1
    local expected_state=$2  # "text" or "encrypted"
    
    if [ ! -f "$file" ]; then
        print_error "Test file not found: $file"
        return 1
    fi
    
    if [[ "$expected_state" == "text" ]]; then
        if file "$file" | grep -q "ASCII text"; then
            return 0
        else
            return 1
        fi
    elif [[ "$expected_state" == "encrypted" ]]; then
        if ! file "$file" | grep -q "ASCII text"; then
            return 0
        else
            return 1
        fi
    fi
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test Execution
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

test_encryption_method() {
    local method=$1
    local method_name=$2
    local step=0
    
    print_section "Testing Method $method: $method_name"
    
    # Step 1: Setup
    ((step+=1))
    print_info "[$step/5] Creating test setup..."
    if ! make test-setup > /dev/null 2>&1; then
        print_error "Test setup failed for method $method"
        return 1
    fi
    
    if ! verify_file_state "$TEST_FILE" "text"; then
        print_error "Initial test file is not in expected state (ASCII text)"
        return 1
    fi
    print_success "Test environment initialized"
    
    # Step 2: Encryption
    ((step+=1))
    print_info "[$step/5] Encrypting test file..."
    if ! make encrypt METHOD="$method" INPUT=$TEST_DIR > /dev/null 2>&1; then
        print_error "Encryption failed for method $method"
        return 1
    fi
    
    # Step 3: Verify encryption
    ((step+=1))
    print_info "[$step/5] Verifying encryption..."
    if ! verify_file_state "$TEST_FILE" "encrypted"; then
        print_error "File was not properly encrypted (still ASCII text)"
        return 1
    fi
    print_success "File successfully encrypted"
    
    # Step 4: Decryption
    ((step+=1))
    print_info "[$step/5] Decrypting test file..."
    if ! make decrypt METHOD="$method" INPUT=$TEST_DIR > /dev/null 2>&1; then
        print_error "Decryption failed for method $method"
        return 1
    fi
    
    # Step 5: Verify decryption
    ((step+=1))
    print_info "[$step/5] Verifying decryption..."
    if ! verify_file_state "$TEST_FILE" "text"; then
        print_error "File was not properly decrypted (not restored to ASCII text)"
        return 1
    fi
    print_success "File successfully decrypted and restored"
    
    # Cleanup
    make clean-test > /dev/null 2>&1
    
    echo -e "${GREEN}${BOLD}✓ Method $method ($method_name) - ALL TESTS PASSED${NC}\n"
    return 0
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main Execution
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

main() {
    print_header
    
    # check_architecture
    build_tools
    
    print_section "Running Encryption Tests"
    print_info "Testing ${#METHODS[@]} encryption methods\n"
    
    local test_num=0
    for method in "${METHODS[@]}"; do
        ((test_num+=1))
        local method_name="${METHOD_NAMES[$((method-1))]}"
        
        if test_encryption_method "$method" "$method_name"; then
            ((TESTS_PASSED+=1))
        else
            ((TESTS_FAILED+=1))
        fi
        
        # Progress indicator
        if [ $test_num -lt ${#METHODS[@]} ]; then
            sleep 0.5  # Brief pause between tests for readability
        fi
    done
    
    print_summary
}

# Trap errors
trap 'print_error "Test suite interrupted or failed"; exit 1' ERR INT TERM

# Execute main
main
exit $?
