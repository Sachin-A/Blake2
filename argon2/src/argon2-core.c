#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "argon2-core.h"
#include "argon2-ref.h"
#include "blake2b.h"


/**
 * load into src 64 bytes at a time
 *
 * @param[in]  dest  the destination
 * @param[out]  src   the source
 */

static uint64_t load64(const void *src) 
{
    #if defined(NATIVE_LITTLE_ENDIAN)
        uint64_t w;
        memcpy(&w, src, sizeof w);
        return w;
    #else
        const uint8_t *p = (const uint8_t *)src;
        uint64_t w = *p++;
        w |= (uint64_t)(*p++) << 8;
        w |= (uint64_t)(*p++) << 16;
        w |= (uint64_t)(*p++) << 24;
        w |= (uint64_t)(*p++) << 32;
        w |= (uint64_t)(*p++) << 40;
        w |= (uint64_t)(*p++) << 48;
        w |= (uint64_t)(*p++) << 56;
        return w;
    #endif
}

/**
 * Stores w into dst
 *
 * @param      dst   the destination
 * @param[in]  w     word to be stored
 */
 
static void store32(void *dst, uint32_t w) 
{
    #if defined(NATIVE_LITTLE_ENDIAN)
        memcpy(dst, &w, sizeof w);
    #else
        uint8_t *p = (uint8_t *)dst;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
    #endif
}


/**
 * Stores w into dst
 *
 * @param      dst   the destination
 * @param[in]  w     word to be stored
 */
 
static void store64(void *dst, uint64_t w) 
{
    #if defined(NATIVE_LITTLE_ENDIAN)
        memcpy(dst, &w, sizeof w);
    #else
        uint8_t *p = (uint8_t *)dst;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
        w >>= 8;
        *p++ = (uint8_t)w;
    #endif
}

#define EQ(x, y) ((((0U - ((unsigned)(x) ^ (unsigned)(y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned)(y) - (unsigned)(x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)
#define LE(x, y) GE(y, x)

/*
 * Convert value x (0..63) to corresponding Base64 character.
 */
static int b64_byte_to_char(unsigned x) {
    return (LT(x, 26) & (x + 'A')) |
           (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
           (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '+') |
           (EQ(x, 63) & '/');
}

/*
 * Convert character c to the corresponding 6-bit value. If character c
 * is not a Base64 character, then 0xFF (255) is returned.
 */
static unsigned b64_char_to_byte(int c) {
    unsigned x;

    x = (GE(c, 'A') & LE(c, 'Z') & (c - 'A')) |
        (GE(c, 'a') & LE(c, 'z') & (c - ('a' - 26))) |
        (GE(c, '0') & LE(c, '9') & (c - ('0' - 52))) | (EQ(c, '+') & 62) |
        (EQ(c, '/') & 63);
    return x | (EQ(x, 0) & (EQ(c, 'A') ^ 0xFF));
}

/*
 * Convert some bytes to Base64. 'dst_len' is the length (in characters)
 * of the output buffer 'dst'; if that buffer is not large enough to
 * receive the result (including the terminating 0), then (size_t)-1
 * is returned. Otherwise, the zero-terminated Base64 string is written
 * in the buffer, and the output length (counted WITHOUT the terminating
 * zero) is returned.
 */
static size_t to_base64(char *dst, size_t dst_len, const void *src,
                        size_t src_len) {
    size_t olen;
    const unsigned char *buf;
    unsigned acc, acc_len;

    olen = (src_len / 3) << 2;
    switch (src_len % 3) {
    case 2:
        olen++;
    /* fall through */
    case 1:
        olen += 2;
        break;
    }
    if (dst_len <= olen) {
        return (size_t)-1;
    }
    acc = 0;
    acc_len = 0;
    buf = (const unsigned char *)src;
    while (src_len-- > 0) {
        acc = (acc << 8) + (*buf++);
        acc_len += 8;
        while (acc_len >= 6) {
            acc_len -= 6;
            *dst++ = (char)b64_byte_to_char((acc >> acc_len) & 0x3F);
        }
    }
    if (acc_len > 0) {
        *dst++ = (char)b64_byte_to_char((acc << (6 - acc_len)) & 0x3F);
    }
    *dst++ = 0;
    return olen;
}

/*
 * Decode Base64 chars into bytes. The '*dst_len' value must initially
 * contain the length of the output buffer '*dst'; when the decoding
 * ends, the actual number of decoded bytes is written back in
 * '*dst_len'.
 *
 * Decoding stops when a non-Base64 character is encountered, or when
 * the output buffer capacity is exceeded. If an error occurred (output
 * buffer is too small, invalid last characters leading to unprocessed
 * buffered bits), then NULL is returned; otherwise, the returned value
 * points to the first non-Base64 character in the source stream, which
 * may be the terminating zero.
 */
static const char *from_base64(void *dst, size_t *dst_len, const char *src) {
    size_t len;
    unsigned char *buf;
    unsigned acc, acc_len;

    buf = (unsigned char *)dst;
    len = 0;
    acc = 0;
    acc_len = 0;
    for (;;) {
        unsigned d;

        d = b64_char_to_byte(*src);
        if (d == 0xFF) {
            break;
        }
        src++;
        acc = (acc << 6) + d;
        acc_len += 6;
        if (acc_len >= 8) {
            acc_len -= 8;
            if ((len++) >= *dst_len) {
                return NULL;
            }
            *buf++ = (acc >> acc_len) & 0xFF;
        }
    }

    /*
     * If the input length is equal to 1 modulo 4 (which is
     * invalid), then there will remain 6 unprocessed bits;
     * otherwise, only 0, 2 or 4 bits are buffered. The buffered
     * bits must also all be zero.
     */
    if (acc_len > 4 || (acc & (((unsigned)1 << acc_len) - 1)) != 0) {
        return NULL;
    }
    *dst_len = len;
    return src;
}

/*
 * Decode decimal integer from 'str'; the value is written in '*v'.
 * Returned value is a pointer to the next non-decimal character in the
 * string. If there is no digit at all, or the value encoding is not
 * minimal (extra leading zeros), or the value does not fit in an
 * 'unsigned long', then NULL is returned.
 */
static const char *decode_decimal(const char *str, unsigned long *v) {
    const char *orig;
    unsigned long acc;

    acc = 0;
    for (orig = str;; str++) {
        int c;

        c = *str;
        if (c < '0' || c > '9') {
            break;
        }
        c -= '0';
        if (acc > (ULONG_MAX / 10)) {
            return NULL;
        }
        acc *= 10;
        if ((unsigned long)c > (ULONG_MAX - acc)) {
            return NULL;
        }
        acc += (unsigned long)c;
    }
    if (str == orig || (*orig == '0' && str != (orig + 1))) {
        return NULL;
    }
    *v = acc;
    return str;
}

/**
 * Decodes an Argon2 hash string into the provided structure 'ctx'.
 * The only fields that must be set prior to this call are ctx.saltlen and
 * ctx.outlen (which must be the maximal salt and out length values that are
 * allowed), ctx.salt and ctx.out (which must be buffers of the specified
 * length), and ctx.pwd and ctx.pwdlen which must hold a valid password.
 *
 * Invalid input string causes an error. On success, the ctx is valid and all
 * fields have been initialized.
 *
 * Returned value is ARGON2_OK on success, other ARGON2_ codes on error.
 */

int decode_string(argon2_context *ctx, const char *str, argon2_type type) 
{
    /**
     * check for prefix 
     */

    #define CC(prefix)                                                             \
        do {                                                                       \
            size_t cc_len = strlen(prefix);                                        \
            if (strncmp(str, prefix, cc_len) != 0) {                               \
                return ARGON2_DECODING_FAIL;                                       \
            }                                                                      \
            str += cc_len;                                                         \
        } while ((void)0, 0)

    /**
     * optional prefix checking with supplied code 
     */

    #define CC_opt(prefix, code)                                                   \
        do {                                                                       \
            size_t cc_len = strlen(prefix);                                        \
            if (strncmp(str, prefix, cc_len) == 0) {                               \
                str += cc_len;                                                     \
                { code; }                                                          \
            }                                                                      \
        } while ((void)0, 0)

    /**
     * Decoding prefix into decimal 
     */

    #define DECIMAL(x)                                                             \
        do {                                                                       \
            unsigned long dec_x;                                                   \
            str = decode_decimal(str, &dec_x);                                     \
            if (str == NULL) {                                                     \
                return ARGON2_DECODING_FAIL;                                       \
            }                                                                      \
            (x) = dec_x;                                                           \
        } while ((void)0, 0)

    /**
     * Decoding base64 into a binary buffer 
     */

    #define BIN(buf, max_len, len)                                                 \
        do {                                                                       \
            size_t bin_len = (max_len);                                            \
            str = from_base64(buf, &bin_len, str);                                 \
            if (str == NULL || bin_len > UINT32_MAX) {                             \
                return ARGON2_DECODING_FAIL;                                       \
            }                                                                      \
            (len) = (uint32_t)bin_len;                                             \
        } while ((void)0, 0)

        size_t maxsaltlen = ctx->saltlen;
        size_t maxoutlen = ctx->outlen;
        int validation_result;
        const char* type_string;

        /**
         * We should start with the argon2_type we are using 
         */

        type_string = argon2_type2string(type, 0);
        if (!type_string) {
            return ARGON2_INCORRECT_TYPE;
        }

        CC("$");
        CC(type_string);

        /**
         * Reading the version number if the default is suppressed 
         */
        
        ctx->version = ARGON2_VERSION_10;
        CC_opt("$v=", DECIMAL(ctx->version));

        CC("$m=");
        DECIMAL(ctx->m_cost);
        CC(",t=");
        DECIMAL(ctx->t_cost);
        CC(",p=");
        DECIMAL(ctx->lanes);
        ctx->threads = ctx->lanes;

        CC("$");
        BIN(ctx->salt, maxsaltlen, ctx->saltlen);
        CC("$");
        BIN(ctx->out, maxoutlen, ctx->outlen);

        /**
         * The rest of the fields get the default values 
         */
        
        ctx->secret = NULL;
        ctx->secretlen = 0;
        ctx->ad = NULL;
        ctx->adlen = 0;
        ctx->allocate_cbk = NULL;
        ctx->free_cbk = NULL;
        ctx->flags = ARGON2_DEFAULT_FLAGS;

        /**
         * On return, must have valid context 
         */
        
        validation_result = 0; 
        if (validation_result != ARGON2_OK) {
            return validation_result;
        }

        /**
         * Can't have any additional characters 
         */
        
        if (*str == 0) {
            return ARGON2_OK;
        } else {
            return ARGON2_DECODING_FAIL;
        }
    #undef CC
    #undef CC_opt
    #undef DECIMAL
    #undef BIN
}

/**
 * encode an Argon2 hash string into the provided buffer. 'dst_len'
 * contains the size, in characters, of the 'dst' buffer; if 'dst_len'
 * is less than the number of required characters (including the
 * terminating 0), then this function returns ARGON2_ENCODING_ERROR.
 *
 * on success, ARGON2_OK is returned.
 */

int encode_string(char *dst, size_t dst_len, argon2_context *ctx, argon2_type type) 
{

    #define SS(str)                                                                \
        do {                                                                       \
            size_t pp_len = strlen(str);                                           \
            if (pp_len >= dst_len) {                                               \
                return ARGON2_ENCODING_FAIL;                                       \
            }                                                                      \
            memcpy(dst, str, pp_len + 1);                                          \
            dst += pp_len;                                                         \
            dst_len -= pp_len;                                                     \
        } while ((void)0, 0)

    #define SX(x)                                                                  \
        do {                                                                       \
            char tmp[30];                                                          \
            sprintf(tmp, "%lu", (unsigned long)(x));                               \
            SS(tmp);                                                               \
        } while ((void)0, 0)

    #define SB(buf, len)                                                           \
        do {                                                                       \
            size_t sb_len = to_base64(dst, dst_len, buf, len);                     \
            if (sb_len == (size_t)-1) {                                            \
                return ARGON2_ENCODING_FAIL;                                       \
            }                                                                      \
            dst += sb_len;                                                         \
            dst_len -= sb_len;                                                     \
        } while ((void)0, 0)

        const char* type_string = argon2_type2string(type, 0);
        int validation_result = 0;

        if (!type_string) {
          return ARGON2_ENCODING_FAIL;
        }

        if (validation_result != ARGON2_OK) {
          return validation_result;
        }


        SS("$");
        SS(type_string);

        SS("$v=");
        SX(ctx->version);

        SS("$m=");
        SX(ctx->m_cost);
        SS(",t=");
        SX(ctx->t_cost);
        SS(",p=");
        SX(ctx->lanes);

        SS("$");
        SB(ctx->salt, ctx->saltlen);

        SS("$");
        SB(ctx->out, ctx->outlen);
        return ARGON2_OK;

    #undef SS
    #undef SX
    #undef SB
}

/**
 * Returns the length of the encoded byte stream with length len 
 */

size_t b64len(uint32_t len) 
{
    size_t olen = ((size_t)len / 3) << 2;

    switch (len % 3) {
    case 2:
        olen++;
    /**
     * fall through 
     */
    case 1:
        olen += 2;
        break;
    }

    return olen;
}

/**
 * Returns the length of the encoded number num 
 */

size_t numlen(uint32_t num) 
{
    size_t len = 1;
    while (num >= 10) {
        ++len;
        num = num / 10;
    }
    return len;
}

/**
 * Creates a thread
 * @param handle pointer to a thread handle, which is the output of this
 * function. Must not be NULL.
 * @param func A function pointer for the thread's entry point. Must not be
 * NULL.
 * @param args Pointer that is passed as an argument to @func. May be NULL.
 * @return 0 if @handle and @func are valid pointers and a thread is successfuly
 * created.
 */
int argon2_thread_create(argon2_thread_handle_t *handle,
                         argon2_thread_func_t func, void *args) 
{
    if (NULL == handle || func == NULL) {
        return -1;
    }
    
    return pthread_create(handle, NULL, func, args);
}

/**
 * Waits for a thread to terminate
 * @param handle Handle to a thread created with argon2_thread_create.
 * @return 0 if @handle is a valid handle, and joining completed successfully.
 */

int argon2_thread_join(argon2_thread_handle_t handle) 
{
    return pthread_join(handle, NULL);
}

/** 
 *Terminate the current thread. Must be run inside a thread created by
 * argon2_thread_create.
 */

void argon2_thread_exit(void) {
    pthread_exit(NULL);
}

/**
 * Initialize each byte of the block with @in 
 */

void init_block_value(block *b, uint8_t in) 
{ 
    memset(b->v, in, sizeof(b->v)); 
}

/**
 * Copy block @src to block @dst 
 */

void copy_block(block *dst, const block *src) 
{
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}

/**
 * XOR @src onto @dst bytewise 
 */

void xor_block(block *dst, const block *src) 
{
    size_t i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] ^= src->v[i];
    }
}


static void load_block(block *dst, const void *input) 
{
    size_t i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        load64((const uint8_t *)input + i * sizeof(dst->v[i]));
    }
}

static void store_block(void *output, const block *src) 
{
    size_t i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}


/** 
 *Allocates memory to the given pointer, uses the appropriate allocator as
 * specified in the context. Total allocated memory is num*size.
 * @param context argon2_context which specifies the allocator
 * @param memory pointer to the pointer to the memory
 * @param size the size in bytes for each element to be allocated
 * @param num the number of elements to be allocated
 * @return ARGON2_OK if @memory is a valid pointer and memory is allocated
 */

int allocate_memory(const argon2_context *context, uint8_t **memory,
                    size_t num, size_t size) 
{
    
    size_t memory_size = num*size;
    
    if ( NULL == memory ) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /**
     * Check for multiplication overflow 
     */

    if (size != 0 && memory_size / size != num) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /**
     * Try to allocate with appropriate allocator 
     */

    if (context->allocate_cbk) {
        (context->allocate_cbk)(memory, memory_size);
    } 
    else {
        *memory = malloc(memory_size);
    }

    if (NULL == *memory) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    return ARGON2_OK;
}


/**
 * Frees memory at the given pointer, uses the appropriate deallocator as
 * specified in the context. Also cleans the memory using clear_internal_memory.
 * @param context argon2_context which specifies the deallocator
 * @param memory pointer to buffer to be freed
 * @param size the size in bytes for each element to be deallocated
 * @param num the number of elements to be deallocated
 */

void free_memory(const argon2_context *context, uint8_t *memory,
                 size_t num, size_t size) 
{
    
    size_t memory_size = num*size;
    
    clear_internal_memory(memory, memory_size);
    
    if (context->free_cbk) {
        (context->free_cbk)(memory, memory_size);
    } 
    else {
        free(memory);
    }
}

/** 
 *Function that securely cleans the memory. This ignores any flags set
 * regarding clearing memory. Usually one just calls clear_internal_memory.
 * @param mem Pointer to the memory
 * @param s Memory size in bytes
 */

void secure_wipe_memory(void *v, size_t n) 
{
    #if defined memset_s
        memset_s(v, n, 0, n);
    #elif defined(__OpenBSD__)
        explicit_bzero(v, n);
    #else
        static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
        memset_sec(v, 0, n);
    #endif
}

/** 
 * Memory clear flag defaults to true. 
 */

 /**
 * Function that securely clears the memory if FLAG_clear_internal_memory is
 * set. If the flag isn't set, this function does nothing.
 * @param mem Pointer to the memory
 * @param s Memory size in bytes
 */

int FLAG_clear_internal_memory = 1;
void clear_internal_memory(void *v, size_t n) 
{
  if (FLAG_clear_internal_memory && v) {
    secure_wipe_memory(v, n);
  }
}

/**
 * XORing the last block of each lane, hashing it, making the tag. Deallocates
 * the memory.
 * @param context Pointer to current Argon2 context (use only the out parameters
 * from it)
 * @param instance Pointer to current instance of Argon2
 * @pre instance->state must point to necessary amount of memory
 * @pre context->out must point to outlen bytes of memory
 * @pre if context->free_cbk is not NULL, it should point to a function that
 * deallocates memory
 */

void finalize(const argon2_context *context, argon2_instance_t *instance) 
{
    if (context != NULL && instance != NULL) {
        
        block blockhash;
        uint32_t l;
        int32_t last_block_in_lane ;
        uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];

        copy_block(&blockhash, instance->memory + instance->lane_length - 1);

        /** 
         * XOR the last blocks 
         */

        for (l = 1; l < instance->lanes; ++l) {
            last_block_in_lane =  l * instance->lane_length + (instance->lane_length - 1);
            xor_block(&blockhash, instance->memory + last_block_in_lane);
        }

        /**
         * Hash the result 
         */
        
        store_block(blockhash_bytes, &blockhash);
        blake2b_long(context->out, context->outlen, blockhash_bytes,
                         ARGON2_BLOCK_SIZE);
        /**
         * clear blockhash and blockhash_bytes 
         */
        
        clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

        free_memory(context, (uint8_t *)instance->memory,
                    instance->memory_blocks, sizeof(block));
    }
}


/**
 * Computes absolute position of reference block in the lane following a skewed
 * distribution and using a pseudo-random value as input
 * @param instance Pointer to the current instance
 * @param position Pointer to the current position
 * @param pseudo_rand 32-bit pseudo-random value used to determine the position
 * @param same_lane Indicates if the block will be taken from the current lane.
 * If so we can reference the current segment
 * @pre All pointers must be valid
 */

uint32_t index_alpha(const argon2_instance_t *instance,
                     const argon2_position_t *position, uint32_t pseudo_rand,
                     int same_lane) 
{
    /**
     * Pass 0:
     *      This lane : all already finished segments plus already constructed
     * blocks in this segment
     *      Other lanes : all already finished segments
     * Pass 1+:
     *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
     * blocks in this segment
     *      Other lanes : (SYNC_POINTS - 1) last segments
     */
    
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (0 == position->pass) {
        /**
         * First pass 
         */

        if (0 == position->slice) {
            /**
             * First slice 
             */

            reference_area_size = position->index - 1; /* all but the previous */
        } 

        else {
            
            if (same_lane) {
                
                /** 
                 * The same lane => add current segment 
                 */
                
                reference_area_size = position->slice * instance->segment_length +  position->index - 1;
            } 

            else {
                reference_area_size =  position->slice * instance->segment_length + ((position->index == 0) ? (-1) : 0);
            }
        }
    } 

    else {
        
        /**
         * Second pass 
         */
        
        if (same_lane) {
            reference_area_size = instance->lane_length -
                                  instance->segment_length + position->index -
                                  1;
        } 

        else {
            reference_area_size = instance->lane_length -
                                  instance->segment_length +
                                  ((position->index == 0) ? (-1) : 0);
        }
    }

    /**
     * Mapping pseudo_rand to 0..<reference_area_size-1> and produce
     * relative position 
     */

    relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 -
                        (reference_area_size * relative_position >> 32);

    /**
     * Computing starting position 
     */

    start_position = 0;

    if (0 != position->pass) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1) ? 0 : (position->slice + 1) * instance->segment_length;
    }

    /**
     * Computing absolute position 
     */

    absolute_position = (start_position + relative_position) %
                        instance->lane_length; /* absolute position */
    return absolute_position;
}


static void *fill_segment_thr(void *thread_data)
{
    argon2_thread_data *my_data = thread_data;
    fill_segment(my_data->instance_ptr, my_data->pos);
    argon2_thread_exit();
    return 0;
}

/**
 * Function that fills the entire memory t_cost times based on the first two
 * blocks in each lane
 * @param instance Pointer to the current instance
 * @return ARGON2_OK if successful, @context->state
 */


int fill_memory_blocks(argon2_instance_t *instance) 
{
    uint32_t r, s;
    argon2_thread_handle_t *thread = NULL;
    argon2_thread_data *thr_data = NULL;
    uint32_t l;

    if (NULL == instance || 0 == instance->lanes) {
        if (thread != NULL) {
            free(thread);
        }
        if (thr_data != NULL) {
            free(thr_data);
        }
        return  ARGON2_THREAD_FAIL;
    }

    /**
     * Allocating space for threads 
     */

    thread = calloc(instance->lanes, sizeof(argon2_thread_handle_t));
    if (NULL == thread) {
        if (thr_data != NULL) {
            free(thr_data);
        }
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    thr_data = calloc(instance->lanes, sizeof(argon2_thread_data));
    if (NULL == thr_data) {
        if (thread != NULL) {
            free(thread);
        }   
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    for (r = 0; r < instance->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            
            /**
             * Calling threads 
             */
            
            for (l = 0; l < instance->lanes; ++l) {
                argon2_position_t position;

                /** 
                 * Join a thread if limit is exceeded 
                 */

                if (l >= instance->threads) {
                    if (argon2_thread_join(thread[l - instance->threads])) {
                        if (thread != NULL) {
                            free(thread);
                        }
                        if (thr_data != NULL) {
                            free(thr_data);
                        }
                        return ARGON2_THREAD_FAIL;
                    }
                }

                /** 
                 * Create thread 
                 */
                position.pass = r;
                position.lane = l;
                position.slice = (uint8_t)s;
                position.index = 0;
                thr_data[l].instance_ptr = instance; /* preparing the thread input */
                memcpy(&(thr_data[l].pos), &position, sizeof(argon2_position_t));
                
                if (argon2_thread_create(&thread[l], &fill_segment_thr, (void *)&thr_data[l])) {
                    if (thread != NULL) {
                        free(thread);
                    }
                    if (thr_data != NULL) {
                        free(thr_data);
                    }
                    return ARGON2_THREAD_FAIL;
                }
            }

            /**
             * Joining remaining threads 
             */
            for (l = instance->lanes - instance->threads; l < instance->lanes; ++l) {
                if (argon2_thread_join(thread[l])) {
                    if (thread != NULL) {
                        free(thread);
                    }
                    if (thr_data != NULL) {
                        free(thr_data);
                    }
                    return ARGON2_THREAD_FAIL;
                }
            }
        }
    }
    if (thread != NULL) {
        free(thread);
    }
    if (thr_data != NULL) {
        free(thr_data);
    }
    return ARGON2_OK;
}

/**
 * Function creates first 2 blocks per lane
 * @param instance Pointer to the current instance
 * @param blockhash Pointer to the pre-hashing digest
 * @pre blockhash must point to @a PREHASH_SEED_LENGTH allocated values
 */

void fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance) 
{
    uint32_t l;

    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
    
    for (l = 0; l < instance->lanes; ++l) {

        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                     ARGON2_PREHASH_SEED_LENGTH);
        load_block(&instance->memory[l * instance->lane_length + 0],
                   blockhash_bytes);

        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                     ARGON2_PREHASH_SEED_LENGTH);
        load_block(&instance->memory[l * instance->lane_length + 1],
                   blockhash_bytes);
    }
    clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
}

/**
 * Hashes all the inputs into @a blockhash[PREHASH_DIGEST_LENGTH], clears
 * password and secret if needed
 * @param  context  Pointer to the Argon2 internal structure containing memory
 * pointer, and parameters for time and space requirements.
 * @param  blockhash Buffer for pre-hashing digest
 * @param  type Argon2 type
 * @pre    @a blockhash must have at least @a PREHASH_DIGEST_LENGTH bytes
 * allocate
 */
void initial_hash(uint8_t *blockhash, argon2_context *context, argon2_type type) 
{
    blake2b_state BlakeHash;
    uint8_t value[sizeof(uint32_t)];
    uint8_t key[] = {};

    if (NULL == context || NULL == blockhash) {
        return;
    }

    blake2b_init(&BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);

    store32(&value, context->lanes);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->outlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->m_cost);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->t_cost);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->version);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, (uint32_t)type);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->pwdlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->pwd != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->pwd,
                       context->pwdlen);

        if (context->flags & ARGON2_FLAG_CLEAR_PASSWORD) {
            secure_wipe_memory(context->pwd, context->pwdlen);
            context->pwdlen = 0;
        }
    }

    store32(&value, context->saltlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->salt != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->salt,
                       context->saltlen);
    }

    store32(&value, context->secretlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->secret != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->secret,
                       context->secretlen);

        if (context->flags & ARGON2_FLAG_CLEAR_SECRET) {
            secure_wipe_memory(context->secret, context->secretlen);
            context->secretlen = 0;
        }
    }

    store32(&value, context->adlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->ad != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->ad,
                       context->adlen);
    }

    blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

/**
 * Function allocates memory, hashes the inputs with Blake,  and creates first
 * two blocks. Returns the pointer to the main memory with 2 blocks per lane
 * initialized
 * @param  context  Pointer to the Argon2 internal structure containing memory
 * pointer, and parameters for time and space requirements.
 * @param  instance Current Argon2 instance
 * @return Zero if successful, -1 if memory failed to allocate. @context->state
 * will be modified if successful.
 */

int initialize(argon2_instance_t *instance, argon2_context *context) 
{
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    int result = ARGON2_OK;

    if (NULL == instance|| NULL == context)
        return ARGON2_INCORRECT_PARAMETER;
    instance->context_ptr = context;

    result = allocate_memory(context, (uint8_t **)&(instance->memory),
                             instance->memory_blocks, sizeof(block));
    if (result != ARGON2_OK) {
        return result;
    }
    initial_hash(blockhash, context, instance->type);
    clear_internal_memory(blockhash + ARGON2_PREHASH_DIGEST_LENGTH,
                          ARGON2_PREHASH_SEED_LENGTH -
                              ARGON2_PREHASH_DIGEST_LENGTH);
    fill_first_blocks(blockhash, instance);
    clear_internal_memory(blockhash, ARGON2_PREHASH_SEED_LENGTH);
    return ARGON2_OK;
}



