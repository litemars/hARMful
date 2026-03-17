# hARMful - Ransomware Research Tool

```
██╗  ██╗ █████╗ ██████╗ ███╗   ███╗███████╗██╗   ██╗██╗          
██║  ██║██╔══██╗██╔══██╗████╗ ████║██╔════╝██║   ██║██║         
███████║███████║██████╔╝██╔████╔██║█████╗  ██║   ██║██║         
██╔══██║██╔══██║██╔══██╗██║╚██╔╝██║██╔══╝  ██║   ██║██║         
██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║██║     ╚██████╔╝███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚══════╝
```

A **Linux Ransomware Framework** demonstrating EDR evasion and defensive security purposes.

## Overview

hARMful is a security research project exploring file encryption, process evasion, and low-level system interactions on Linux systems. The project implements multiple encryption strategies using direct syscalls, io_uring async I/O, and hybrid approaches, while incorporating detection evasion techniques for analyzing malware behavior and defensive mechanisms.

**⚠️ Educational Purpose Only**: This project is intended solely for authorized security research, penetration testing, and defensive analysis within controlled environments.

## Key Features

- **Multi-Architecture Support**: Seamless execution on ARM64 and x86-64 Linux systems with architecture-specific syscall handling
- **Six Encryption Methods**:
  - Direct syscall-based encryption
  - io_uring asynchronous I/O encryption
  - Partial/strategic file encryption
  - Memory-mapped page encryption
  - io_uring with direct syscalls
  - Hybrid io_uring partial encryption
- **Advanced Syscall Operations**: Direct syscall invocation bypassing libc wrappers
- **io_uring Integration**: High-performance async I/O operations via Linux kernel's io_uring API
- **ChaCha20 & XOR Encryption**: Multiple cipher implementations for data protection
- **EDR Evasion Detection**: Virtualization detection, debugging tool identification, security product scanning
- **Multi-threaded Processing**: Concurrent file encryption with configurable worker threads


## Technical Details

### Encryption Methods

1. **Direct Syscall** (`METHOD_DIRECT_SYSCALL`): Traditional file I/O using direct Linux syscalls (read/write)
2. **io_uring** (`METHOD_IO_URING`): Asynchronous I/O using liburing library
3. **Partial Encryption** (`METHOD_PARTIAL`): Strategic encryption of file chunks (beginning/middle/end)
4. **Memory-Mapped Pages** (`METHOD_MMAP_PAGES`): mmap-based encryption for efficient memory handling
5. **io_uring Direct Syscall** (`METHOD_IO_URING_SYSCALL`): io_uring operations via raw syscalls
6. **Hybrid io_uring Partial** (`METHOD_IO_URING_SYSCALL_HYBRID`): Combined approach for optimized performance

### Architecture Support

**ARM64 Syscall Numbers**:
- read: 63, write: 64, openat: 56, close: 57, lseek: 62
- mmap: 222, munmap: 215, mprotect: 226, fstat: 80
- io_uring_setup: 425, io_uring_enter: 426

**x86-64 Syscall Numbers**:
- read: 0, write: 1, openat: 257, close: 3, lseek: 8
- mmap: 9, munmap: 11, mprotect: 10, fstat: 5
- io_uring_setup: 425, io_uring_enter: 426


## Building

### Prerequisites

- Linux kernel with io_uring support (5.1+)
- GCC or Clang with ARM64/x86-64 cross-compilation support
- liburing development headers (optional, for io_uring method)
- GNU Make

### Build Commands

```bash
# Build for native architecture
make

# Clean build artifacts
make clean

# View all available targets
make help
```

The build system compiles binaries into the `build/` directory with architecture-specific organization.

## Usage

```bash
./hARMful -m <method> (-t <threads>) <target_directory>
./decrypt_tool <target_directory> <method>
```

### Options

- `-m <method>`: Encryption method (1-6)
  - `1`: Direct syscalls (default)
  - `2`: io_uring
  - `3`: Partial encryption
  - `4`: Memory-mapped pages
  - `5`: io_uring Direct syscall
  - `6`: io_uring Hybrid Partial
- `-t <threads>`: Number of worker threads (1-8, default: 4)
- `-h`: Display help information

### Example Usage

```bash
# Encrypt files in /tmp/test with 4 threads using partial encryption
./hARMful -m 3 -t 4 /tmp/test_files
```

## Limitations

- Designed for research purposes only
- No persistence mechanisms (outside test scope)


## License

This project is provided for educational and authorized security research purposes. Unauthorized access to computer systems is illegal. Users assume full responsibility for lawful use.

## Contributing

Contributions for defensive improvements and detection enhancements are welcome in authorized research contexts.

## References

- [Linux io_uring Documentation](https://kernel.dk/io_uring.pdf)
- [ARM64 SYSCALL ABI](https://github.com/ARM-software/abi-aa/releases)
- [x86-64 System V ABI](https://refspecs.linuxfoundation.org/elf/x86-64-abi-0.99.pdf)
- [ChaCha20 Cipher Specification](https://tools.ietf.org/html/rfc7539)

## Disclaimer

This software is provided AS IS for educational purposes. The authors are not responsible for misuse, unauthorized access, or violations of applicable laws. Always obtain proper authorization before conducting security research.
