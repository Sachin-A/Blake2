#ifdef __cplusplus
extern "C" {
#endif
    
#ifndef ARGON2_CORE_H
#define ARGON2_CORE_H

#include "argon2.h"
#include <pthread.h>

enum argon2_core_constants {
    ARGON2_BLOCK_SIZE = 1024,
    ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8,
    ARGON2_OWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 16,
    ARGON2_ADDRESSES_IN_BLOCK = 128,
    ARGON2_PREHASH_DIGEST_LENGTH = 64,
    ARGON2_PREHASH_SEED_LENGTH = 72
};

#define ARGON2_MAX_DECODED_LANES UINT32_C(255)
#define ARGON2_MIN_DECODED_SALT_LEN UINT32_C(8)
#define ARGON2_MIN_DECODED_OUT_LEN UINT32_C(12)
#define CONST_CAST(x) (x)(uintptr_t)

int encode_string(char *dst, size_t dst_len, argon2_context *ctx, argon2_type type);
int decode_string(argon2_context *ctx, const char *str, argon2_type type);
size_t b64len(uint32_t len);
size_t numlen(uint32_t num);

typedef void *(*argon2_thread_func_t)(void *);
typedef pthread_t argon2_thread_handle_t;

int argon2_thread_create(argon2_thread_handle_t *handle, argon2_thread_func_t func, void *args);
int argon2_thread_join(argon2_thread_handle_t handle);
void argon2_thread_exit(void) ;

typedef struct block_ { uint64_t v[ARGON2_QWORDS_IN_BLOCK]; } block;
void init_block_value(block *b, uint8_t in);
void copy_block(block *dst, const block *src);
void xor_block(block *dst, const block *src);


/**
 * Argon2 instance: memory pointer, number of passes, amount of memory, type,
 * and derived values.
 * Used to evaluate the number and location of blocks to construct in each
 * thread
 */

typedef struct Argon2_instance_t {
    block *memory;          /* Memory pointer */
    uint32_t version;
    uint32_t passes;        /* Number of passes */
    uint32_t memory_blocks; /* Number of blocks in memory */
    uint32_t segment_length;
    uint32_t lane_length;
    uint32_t lanes;
    uint32_t threads;
    argon2_type type;
    int print_internals; /* whether to print the memory blocks */
    argon2_context *context_ptr; /* points back to original context */
} argon2_instance_t;

/**
 * Argon2 position: where we construct the block right now. Used to distribute
 * work between threads.
 */

typedef struct Argon2_position_t {
    uint32_t pass;
    uint32_t lane;
    uint8_t slice;
    uint32_t index;
} argon2_position_t;

/**
 * Struct that holds the inputs for thread handling FillSegment
 */

typedef struct Argon2_thread_data {
    argon2_instance_t *instance_ptr;
    argon2_position_t pos;
} argon2_thread_data;

/**
 * Argon2 Core Functions
 */

int allocate_memory(const argon2_context *context, uint8_t **memory,size_t num, size_t size);
void free_memory(const argon2_context *context, uint8_t *memory, size_t num, size_t size);
void secure_wipe_memory(void *v, size_t n);
void clear_internal_memory(void *v, size_t n);

uint32_t index_alpha(const argon2_instance_t *instance, const argon2_position_t *position, uint32_t pseudo_rand, int same_lane);
void initial_hash(uint8_t *blockhash, argon2_context *context, argon2_type type);
void fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance);
int initialize(argon2_instance_t *instance, argon2_context *context);
void finalize(const argon2_context *context, argon2_instance_t *instance);
int fill_memory_blocks(argon2_instance_t *instance);


#endif /* ARGON2_CORE_H */

#ifdef __cplusplus
}
#endif