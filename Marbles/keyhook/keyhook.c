/*
 * LD_PRELOAD hook library to intercept encryption functions and log shared secrets.
 * 
 * This library hooks into the imix encryption functions to capture shared secrets
 * as they're generated during X25519 key exchange.
 * 
 * Compile: gcc -shared -fPIC -o keyhook.so keyhook.c -ldl
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Function pointer types */
typedef void (*add_key_history_func)(const unsigned char* pub_key, const unsigned char* shared_secret);

/* Original function pointers */
static add_key_history_func original_add_key_history = NULL;

/* Key log file path */
static const char* KEYLOG_PATH = NULL;

/* Initialize key log path from environment */
static void init_keylog_path() {
    if (KEYLOG_PATH == NULL) {
        const char* env_path = getenv("XCHACHA_KEYLOG");
        if (env_path) {
            KEYLOG_PATH = env_path;
        } else {
            KEYLOG_PATH = "/tmp/xchacha_keys.log";
        }
    }
}

/* Write key pair to log file */
static void log_key_pair(const unsigned char* pub_key, const unsigned char* shared_secret) {
    init_keylog_path();
    
    FILE* f = fopen(KEYLOG_PATH, "a");
    if (f == NULL) {
        return;
    }
    
    /* Write in hex format: pub_key_hex:shared_secret_hex */
    for (int i = 0; i < 32; i++) {
        fprintf(f, "%02x", pub_key[i]);
    }
    fprintf(f, ":");
    for (int i = 0; i < 32; i++) {
        fprintf(f, "%02x", shared_secret[i]);
    }
    fprintf(f, "\n");
    
    fclose(f);
}

/* Hook for add_key_history function */
void add_key_history(const unsigned char* pub_key, const unsigned char* shared_secret) {
    /* Log the key pair */
    log_key_pair(pub_key, shared_secret);
    
    /* Call original function if available */
    if (original_add_key_history == NULL) {
        /* Try to get original function */
        original_add_key_history = (add_key_history_func)dlsym(RTLD_NEXT, "add_key_history");
    }
    
    if (original_add_key_history != NULL) {
        original_add_key_history(pub_key, shared_secret);
    }
}

/* Constructor - called when library is loaded */
__attribute__((constructor))
static void init() {
    init_keylog_path();
    /* Note: We can't easily hook Rust functions directly with LD_PRELOAD
     * This is a placeholder - actual implementation may need different approach
     * such as ptrace or binary patching */
}
