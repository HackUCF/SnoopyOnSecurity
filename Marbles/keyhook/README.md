# Keyhook Library

LD_PRELOAD hook library to intercept encryption functions and log shared secrets.

## Building

```bash
make
```

This creates `keyhook.so` which can be used with `LD_PRELOAD`.

## Usage

Set environment variables:
- `XCHACHA_KEYLOG`: Path to key log file (default: `/tmp/xchacha_keys.log`)
- `LD_PRELOAD`: Path to `keyhook.so`

## Note

Hooking Rust functions directly with LD_PRELOAD is challenging. This implementation
may need to be adapted based on the actual binary structure. Alternative approaches:
- ptrace-based hooking
- Binary patching
- Process memory inspection
