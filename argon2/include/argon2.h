#ifndef ARGON2_H
#define ARGON2_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>


/* TODO */
/* Argon2 Input Restrictions */

/* Number of synchronization points between lanes per pass */
#define ARGON2_SYNC_POINTS UINT32_C(4)

/* Minimum and maximum number of lanes (degree of parallelism) */
#define ARGON2_MIN_LANES UINT32_C(1)
#define ARGON2_MAX_LANES UINT32_C(0xFFFFFF)

/* Minimum and maximum number of threads */
#define ARGON2_MIN_THREADS UINT32_C(1)
#define ARGON2_MAX_THREADS UINT32_C(0xFFFFFF)

/* Minimum and maximum digest size in bytes */
#define ARGON2_MIN_OUTLEN UINT32_C(4)
#define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)

/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
#define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS) /* 2 blocks per slice */

#define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
/* Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
#define ARGON2_MAX_MEMORY_BITS                                                 \
    ARGON2_MIN(UINT32_C(32), (sizeof(void *) * CHAR_BIT - 10 - 1))
#define ARGON2_MAX_MEMORY                                                      \
    ARGON2_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2_MAX_MEMORY_BITS)

/* Minimum and maximum number of passes */
#define ARGON2_MIN_TIME UINT32_C(1)
#define ARGON2_MAX_TIME UINT32_C(0xFFFFFFFF)

/* Minimum and maximum password length in bytes */
#define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
#define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum associated data length in bytes */
#define ARGON2_MIN_AD_LENGTH UINT32_C(0)
#define ARGON2_MAX_AD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum salt length in bytes */
#define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
#define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum key length in bytes */
#define ARGON2_MIN_SECRET UINT32_C(0)
#define ARGON2_MAX_SECRET UINT32_C(0xFFFFFFFF)

/* Flags to determine which fields are securely wiped (default = no wipe). */
#define ARGON2_DEFAULT_FLAGS UINT32_C(0)
#define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)
#define ARGON2_FLAG_CLEAR_SECRET (UINT32_C(1) << 1)

/* Global flag to determine if we are wiping internal memory buffers. This flag
 * is defined in core.c and deafults to 1 (wipe internal memory). */
extern int FLAG_clear_internal_memory;

/* Error codes */
typedef enum Argon2_ErrorCodes {
    ARGON2_OK = 0,

    ARGON2_OUTPUT_PTR_NULL = -1,

    ARGON2_OUTPUT_TOO_SHORT = -2,
    ARGON2_OUTPUT_TOO_LONG = -3,

    ARGON2_PWD_TOO_SHORT = -4,
    ARGON2_PWD_TOO_LONG = -5,

    ARGON2_SALT_TOO_SHORT = -6,
    ARGON2_SALT_TOO_LONG = -7,

    ARGON2_AD_TOO_SHORT = -8,
    ARGON2_AD_TOO_LONG = -9,

    ARGON2_SECRET_TOO_SHORT = -10,
    ARGON2_SECRET_TOO_LONG = -11,

    ARGON2_TIME_TOO_SMALL = -12,
    ARGON2_TIME_TOO_LARGE = -13,

    ARGON2_MEMORY_TOO_LITTLE = -14,
    ARGON2_MEMORY_TOO_MUCH = -15,

    ARGON2_LANES_TOO_FEW = -16,
    ARGON2_LANES_TOO_MANY = -17,

    ARGON2_PWD_PTR_MISMATCH = -18,    /* NULL ptr with non-zero length */
    ARGON2_SALT_PTR_MISMATCH = -19,   /* NULL ptr with non-zero length */
    ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
    ARGON2_AD_PTR_MISMATCH = -21,     /* NULL ptr with non-zero length */

    ARGON2_MEMORY_ALLOCATION_ERROR = -22,

    ARGON2_FREE_MEMORY_CBK_NULL = -23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

    ARGON2_INCORRECT_PARAMETER = -25,
    ARGON2_INCORRECT_TYPE = -26,

    ARGON2_OUT_PTR_MISMATCH = -27,

    ARGON2_THREADS_TOO_FEW = -28,
    ARGON2_THREADS_TOO_MANY = -29,

    ARGON2_MISSING_ARGS = -30,

    ARGON2_ENCODING_FAIL = -31,

    ARGON2_DECODING_FAIL = -32,

    ARGON2_THREAD_FAIL = -33,

    ARGON2_DECODING_LENGTH_FAIL = -34,

    ARGON2_VERIFY_MISMATCH = -35
} argon2_error_codes;

/* Memory allocator types --- for external allocation */
typedef int (*allocate_fptr)(uint8_t **memory, size_t bytes_to_allocate);
typedef void (*deallocate_fptr)(uint8_t *memory, size_t bytes_to_allocate);


/* Argon2 External Data Structures */

/*
 * Structure to hold Argon2 inputs
 * output array and its length,
 * password and its length,
 * salt and its length,
 * secret and its length,
 * associated data and its length,
 * number of passes, amount of used memory (in KBytes, can be rounded up a bit)
 * number of parallel threads that will be run.
 */
typedef struct Argon2_state {
    uint8_t *out;    /* output array */
    uint32_t outlen; /* digest length */

    uint8_t *pwd;    /* password array */
    uint32_t pwdlen; /* password length */

    uint8_t *salt;    /* salt array */
    uint32_t saltlen; /* salt length */

    uint8_t *secret;    /* key array */
    uint32_t secretlen; /* key length */

    uint8_t *ad;    /* associated data array */
    uint32_t adlen; /* associated data length */

    uint32_t t_cost;  /* number of passes */
    uint32_t m_cost;  /* amount of memory requested (KB) */
    uint32_t lanes;   /* number of lanes */
    uint32_t threads; /* maximum number of threads */

    uint32_t version; /* version number */

    allocate_fptr allocate_cbk; /* pointer to memory allocator */
    deallocate_fptr free_cbk;   /* pointer to memory deallocator */

    uint32_t flags; /* array of bool options */
} argon2_state;

/*
 * Argon2 primitive type 
 * NOTE: Other types not implemented
 */
 typedef enum Argon2_type {
    Argon2_d = 0,
    Argon2_i = 1,
    Argon2_id = 2
 } argon2_type;

/* Version of the algorithm */
typedef enum Argon2_version {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

/* TODO: Make the functions visible (ARGON2_PUBLIC) 
  Expose the functions corresponding to i/d/id */

/*
 * Function that gives the string representation of an argon2_type.
 * @param type The argon2_type that we want the string for
 * @param uppercase Whether the string should have the first letter uppercase
 * @return NULL if invalid type, otherwise the string representation.
 */
const char *argon2_type2string(argon2_type type, int uppercase);

/*
 * Function that performs memory-hard hashing with certain degree of parallelism
 * @param  context  Pointer to the Argon2 internal structure
 * @return Error code if smth is wrong, ARGON2_OK otherwise
 */
int argon2_state(argon2_state *state, argon2_type type);

/**
 * Hashes a password with Argon2i, producing an encoded hash
 * @param t_cost Number of iterations
 * @param m_cost Sets memory usage to m_cost kibibytes
 * @param parallelism Number of threads and compute lanes
 * @param pwd Pointer to password
 * @param pwdlen Password size in bytes
 * @param salt Pointer to salt
 * @param saltlen Salt size in bytes
 * @param hashlen Desired length of the hash in bytes
 * @param encoded Buffer where to write the encoded hash
 * @param encodedlen Size of the buffer (thus max size of the encoded hash)
 * @pre   Different parallelism levels will give different results
 * @pre   Returns ARGON2_OK if successful
 */
int argon2i_hash_encoded(const uint32_t t_cost,
                                       const uint32_t m_cost,
                                       const uint32_t parallelism,
                                       const void *pwd, const size_t pwdlen,
                                       const void *salt, const size_t saltlen,
                                       const size_t hashlen, char *encoded,
                                       const size_t encodedlen);

/**
 * Hashes a password with Argon2i, producing a raw hash by allocating memory at
 * @hash
 * @param t_cost Number of iterations
 * @param m_cost Sets memory usage to m_cost kibibytes
 * @param parallelism Number of threads and compute lanes
 * @param pwd Pointer to password
 * @param pwdlen Password size in bytes
 * @param salt Pointer to salt
 * @param saltlen Salt size in bytes
 * @param hash Buffer where to write the raw hash - updated by the function
 * @param hashlen Desired length of the hash in bytes
 * @pre   Different parallelism levels will give different results
 * @pre   Returns ARGON2_OK if successful
 */
int argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                                   const uint32_t parallelism, const void *pwd,
                                   const size_t pwdlen, const void *salt,
                                   const size_t saltlen, void *hash,
                                   const size_t hashlen);

int argon2d_hash_encoded(const uint32_t t_cost,
                                       const uint32_t m_cost,
                                       const uint32_t parallelism,
                                       const void *pwd, const size_t pwdlen,
                                       const void *salt, const size_t saltlen,
                                       const size_t hashlen, char *encoded,
                                       const size_t encodedlen);

int argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                                   const uint32_t parallelism, const void *pwd,
                                   const size_t pwdlen, const void *salt,
                                   const size_t saltlen, void *hash,
                                   const size_t hashlen);

int argon2id_hash_encoded(const uint32_t t_cost,
                                        const uint32_t m_cost,
                                        const uint32_t parallelism,
                                        const void *pwd, const size_t pwdlen,
                                        const void *salt, const size_t saltlen,
                                        const size_t hashlen, char *encoded,
                                        const size_t encodedlen);

int argon2id_hash_raw(const uint32_t t_cost,
                                    const uint32_t m_cost,
                                    const uint32_t parallelism, const void *pwd,
                                    const size_t pwdlen, const void *salt,
                                    const size_t saltlen, void *hash,
                                    const size_t hashlen);

/* Generic hash */  
int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
                              const uint32_t parallelism, const void *pwd,
                              const size_t pwdlen, const void *salt,
                              const size_t saltlen, void *hash,
                              const size_t hashlen, char *encoded,
                              const size_t encodedlen, argon2_type type,
                              const uint32_t version);

/**
 * Verifies a password against an encoded string
 * Encoded string is restricted as in validate_inputs()
 * @param encoded String encoding parameters, salt, hash
 * @param pwd Pointer to password
 * @pre   Returns ARGON2_OK if successful
 */
int argon2i_verify(const char *encoded, const void *pwd,
                                 const size_t pwdlen);

int argon2d_verify(const char *encoded, const void *pwd,
                                 const size_t pwdlen);

int argon2id_verify(const char *encoded, const void *pwd,
                                  const size_t pwdlen);

/* Generic verify */
int argon2_verify(const char *encoded, const void *pwd,
                                const size_t pwdlen, argon2_type type);

/**
 * Argon2d: Version of Argon2 that picks memory blocks depending
 * on the password and salt. Only for side-channel-free
 * environment!!
 *****
 * @param  context  Pointer to current Argon2 context
 * @return  Zero if successful, a non zero error code otherwise
 */
int argon2d_ctx(argon2_state *state);

/**
 * Argon2i: Version of Argon2 that picks memory blocks
 * independent on the password and salt. Good for side-channels,
 * but worse w.r.t. tradeoff attacks if only one pass is used.
 *****
 * @param  context  Pointer to current Argon2 context
 * @return  Zero if successful, a non zero error code otherwise
 */
int argon2i_ctx(argon2_state *state);

/**
 * Argon2id: Version of Argon2 where the first half-pass over memory is
 * password-independent, the rest are password-dependent (on the password and
 * salt). OK against side channels (they reduce to 1/2-pass Argon2i), and
 * better with w.r.t. tradeoff attacks (similar to Argon2d).
 *****
 * @param  context  Pointer to current Argon2 context
 * @return  Zero if successful, a non zero error code otherwise
 */
int argon2id_ctx(argon2_state *state);

/**
 * Verify if a given password is correct for Argon2d hashing
 * @param  context  Pointer to current Argon2 context
 * @param  hash  The password hash to verify. The length of the hash is
 * specified by the context outlen member
 * @return  Zero if successful, a non zero error code otherwise
 */
int argon2d_verify_ctx(argon2_state *state, const char *hash);

/**
 * Verify if a given password is correct for Argon2i hashing
 * @param  context  Pointer to current Argon2 context
 * @param  hash  The password hash to verify. The length of the hash is
 * specified by the context outlen member
 * @return  Zero if successful, a non zero error code otherwise
 */
int argon2i_verify_ctx(argon2_state *state, const char *hash);

/**
 * Verify if a given password is correct for Argon2id hashing
 * @param  context  Pointer to current Argon2 context
 * @param  hash  The password hash to verify. The length of the hash is
 * specified by the context outlen member
 * @return  Zero if successful, a non zero error code otherwise
 */
int argon2id_verify_ctx(argon2_state *state,
                                      const char *hash);

/* Generic verify context/state */
int argon2_verify_ctx(argon2_state *state, const char *hash,
                                    argon2_type type);

/**
 * Get the associated error message for given error code
 * @return  The error message associated with the given error code
 */
const char *argon2_error_message(int error_code);

/**
 * Returns the encoded hash length for the given input parameters
 * @param t_cost  Number of iterations
 * @param m_cost  Memory usage in kibibytes
 * @param parallelism  Number of threads; used to compute lanes
 * @param saltlen  Salt size in bytes
 * @param hashlen  Hash size in bytes
 * @param type The argon2_type that we want the encoded length for
 * @return  The encoded hash length in bytes
 */
size_t argon2_encodedlen(uint32_t t_cost, uint32_t m_cost,
                                       uint32_t parallelism, uint32_t saltlen,
                                       uint32_t hashlen, argon2_type type);

#endif