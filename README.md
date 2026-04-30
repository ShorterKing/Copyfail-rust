# Copy Fail (Rust Implementation of CVE-2026-31431: Page Cache Overwrite Exploit)

`copy_fail` is a Rust-based proof-of-concept (PoC) exploit that leverages a vulnerability in the Linux kernel (using the `AF_ALG` socket family and `splice()` system calls) to overwrite read-only files in the page cache. Specifically, it targets the `su` binary to achieve privilege escalation.

## Features

* **Page Cache Overwriting**: Overwrites the `su` binary in memory (page cache) without modifying the actual file on the disk (unless memory is synced/dropped).
* **Multi-Architecture Support**: Includes zlib-compressed payloads for `x86_64`, `x86`, and `aarch64`.
* **Backup Functionality**: Optionally backs up the original `su` binary before exploitation.
* **Custom Execution**: Allows specifying a custom command to execute as root via the overwritten `su`.

## Prerequisites

* Rust toolchain (`cargo`, `rustc`)
* A vulnerable Linux kernel

## Usage

Build the project using Cargo:
```bash
cargo build --release
```

Run the compiled executable:

```bash
./target/release/copy_fail [OPTIONS]
```

## Options

* `-backup <path>`: Path to copy the `su` binary to before overwriting. This creates a backup of the original binary with its original permissions.
* `-exec <command>`: Command to run as root. A full path to the executable is required.
* `-h`, `--help`: Print the help menu.

## Examples

**Run with the default payload:**
```bash
./target/release/copy_fail
```

**Run and backup the original `su` binary:**
```bash
./target/release/copy_fail -backup /tmp/su_backup
```

**Run and execute a custom command as root:**
```bash
./target/release/copy_fail -exec /bin/bash
```

## Why Rust?

BECAUSE WHY NOT 😂

## Dependencies

* `libc`: For raw system calls and interacting with the Linux socket API (`AF_ALG`, `splice`, `sendmsg`, etc.).
* `flate2`: For decompressing the zlib-compressed shellcode payloads.
* `hex`: For decoding hex-encoded payloads.

## Disclaimer

**This software is provided for educational and research purposes only.** Do not use this tool on systems you do not own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.