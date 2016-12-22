#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

  /** 
   * BLAKE2s Initialization Vector. 
   */

  static const uint32_t blake2s_IV[8] =
  {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
  };

  /**
   * Table of permutations 
   */

 static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
  };

  enum blake2s_constant
  {
    BLAKE2S_BLOCKBYTES = 64,
    BLAKE2S_OUTBYTES   = 32,
    BLAKE2S_KEYBYTES   = 32,
    BLAKE2S_SALTBYTES  = 8,
    BLAKE2S_PERSONALBYTES = 8
  };

  typedef struct blake2s_state
  {
    uint32_t h[8];            /* Chained state */
    uint32_t t[2];            /* Total number of bytes */
    uint32_t f[2];            /* Last block flag */
    uint8_t  buf[BLAKE2S_BLOCKBYTES]; /* Input buffer */
    size_t   buflen; /* size of buffer */
    size_t   outlen; /* digest (output) size */
  } blake2s_state;

  typedef struct blake2s_param
  {
    uint8_t digest_length;                   /* 1 */
    uint8_t key_length;                      /* 2 */
    uint8_t fanout;                          /* 3 */
    uint8_t depth;                           /* 4 */
    uint32_t leaf_length;                    /* 8 */
    uint32_t node_offset;                    /* 12 */
    uint16_t xof_length;                     /* 14 */
    uint8_t node_depth;                      /* 15 */
    uint8_t inner_length;                    /* 16 */
    uint8_t salt[BLAKE2S_SALTBYTES];         /* 24 */
    uint8_t personal[BLAKE2S_PERSONALBYTES]; /* 32 */
  } blake2s_param;
  

  /* Streaming API */
  extern int blake2s_init(blake2s_state* S, size_t outlen, const void* key, size_t keylen);
  extern int blake2s_update( blake2s_state *S, const void *in, size_t inlen );
  extern int blake2s_final( blake2s_state *S, void *out, size_t outlen );
  extern int blake2s(void* output, size_t outlen, const void* input, size_t inlen, const void* key, size_t keylen);

#endif /* BLAKE_H */
