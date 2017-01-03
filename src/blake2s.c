#include "blake2s.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


/**
 * Helper macro to perform rotation in a 32 bit int
 *
 * @param[in]  w     original word
 * @param[in]  c     offset to rotate by
 */

#define ROTR32(w, c) ((w) >> (c)) | ((w) << (32 - (c)))

/**
 * Helper macro to load into src 32 bytes at a time
 *
 * @param[in]  dest  the destination
 * @param[in]  src   the source
 */

#if defined(NATIVE_LITTLE_ENDIAN)
  #define LOAD32(dest, src) memcpy(&(dest), (src), sizeof (dest))
#else
  #define LOAD32(dest, src)                                          \
    do {                                                             \
    const uint8_t* load = (const uint8_t*)(src);                     \
    dest = ((uint64_t)(load[0]) <<  0) |                             \
           ((uint64_t)(load[1]) <<  8) |                             \
           ((uint64_t)(load[2]) << 16) |                             \
           ((uint64_t)(load[3]) << 24);                              \
    } while(0)
#endif

/**
 * Stores w into dst
 *
 * @param      dst   the destination
 * @param[in]  w     word to be stored
 */

void store16( uint8_t* dst, uint16_t w )
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = dst;
  p[0] = ( uint8_t )(w >> 0); 
  p[1] = ( uint8_t )(w >> 8);
#endif
}

/**
 * Stores w into dst
 *
 * @param      dst   the destination
 * @param[in]  w     word to be stored
 */
 

void store32(uint8_t* dst, uint32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t* p = dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}


/**
 * Increments the blake2s state counter
 *
 * @param      state     blake2s_state instance
 * @param[in]  inc   the increment value
 */

void blake2s_increment_counter(blake2s_state* state, const uint32_t inc)
{
  state->t[0] += inc ;
  state->t[1] += (state->t[0] < inc);
}

/**
 * The blake2s mixing function like macro mixes two 8-byte words from the message
 * into the hash state
 *
 * @params  a, b, c, d  indices to 8-byte word entries from the work vector V
 * @params  x, y        two 8-byte word entries from padded message v
 */


#define G(a, b, c, d, x, y)       \
  do {                            \
  a = a + b + x;                  \
  d = ROTR32(d ^ a, 16);          \
  c = c + d;                      \
  b = ROTR32(b ^ c, 12);          \
  a = a + b + y;                  \
  d = ROTR32(d ^ a,  8);          \
  c = c + d;                      \
  b = ROTR32(b ^ c,  7);          \
  } while(0)

/**
 * The blake2s compress function which takes a full 64-byte chunk of the
 * input message and mixes it into the ongoing state array
 *
 * @param      state  blake2s_state instance
 * @param      block  the input block
 */

static void F(blake2s_state* state, const uint8_t block[BLAKE2S_BLOCKBYTES])
{
  size_t i, j;
  uint32_t v[16], s[16], m[16];

  for( i = 0; i < 16; ++i ) {
     LOAD32( m[i], block + i * sizeof( m[i] ) );
  }

  for (i = 0; i < 8; ++i) {
    v[i] = state->h[i];
    v[i + 8] = blake2s_IV[i];
  }

  v[12] ^= state->t[0];
  v[13] ^= state->t[1];
  v[14] ^= state->f[0];
  v[15] ^= state->f[1];

  for (i = 0; i < 10; i++) {
    for (j = 0; j < 16; j++) {
      s[j] = blake2s_sigma[i][j];
    }   
    G(v[0], v[4],  v[8], v[12],  m[s[0]],  m[s[1]]);
    G(v[1], v[5],  v[9], v[13],  m[s[2]],  m[s[3]]);
    G(v[2], v[6], v[10], v[14],  m[s[4]],  m[s[5]]);
    G(v[3], v[7], v[11], v[15],  m[s[6]],  m[s[7]]);
    G(v[0], v[5], v[10], v[15],  m[s[8]],  m[s[9]]);
    G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
    G(v[2], v[7],  v[8], v[13], m[s[12]], m[s[13]]);
    G(v[3], v[4],  v[9], v[14], m[s[14]], m[s[15]]);
  }

  for (i = 0; i < 8; i++) {
    state->h[i] = state->h[i] ^ v[i] ^ v[i + 8];
  }
}

/**
 * Initializes blake2s state
 *
 * @param      state   blake2s_state instance passed by reference
 * @param[in]  outlen  the hash output length
 * @param[in]  key     the key used
 * @param[in]  keylen  the key length
 */

void blake2s_init(blake2s_state* state, size_t outlen, const void* key, size_t keylen)
{
  blake2s_param P = {0};
  const uint8_t* p;
  size_t i;
  uint32_t dest;

  /* initialize key */
  
  P.digest_length = (uint8_t)outlen;
  P.key_length = (uint8_t)keylen;
  P.fanout = 1;
  P.depth = 1;
  store32(( uint8_t * )&P.leaf_length, 0);
  store32(( uint8_t * )&P.node_offset, 0);
  store16(( uint8_t * )&P.xof_length, 0);
  P.node_depth = 0;
  P.inner_length = 0;
  memset(P.salt, 0, sizeof(P.salt));
  memset(P.personal, 0, sizeof(P.personal));

  /*initialize param*/

  p = (const uint8_t*)(&P); 
  memset(state, 0, sizeof(blake2s_state));

  for (i = 0; i < 8; ++i){
    state->h[i] = blake2s_IV[i];
  }
  for (i = 0; i < 8; ++i){
    LOAD32(dest, p + sizeof(state->h[i]) * i);
    state->h[i] ^= dest;
   }
  state->outlen = P.digest_length;

  if (keylen > 0) {
    uint8_t block[BLAKE2S_BLOCKBYTES];
    memset(block, 0, BLAKE2S_BLOCKBYTES);
    memcpy(block, key, keylen);
    blake2s_update(state, block, BLAKE2S_BLOCKBYTES);
    
  }
}

/**
 * Updates blake2s state
 *
 * @param      state         blake2s state instance
 * @param[in]  input_buffer  the input buffer
 * @param[in]  inlen         the input length
 */

void blake2s_update(blake2s_state* state, const unsigned char* input_buffer, size_t inlen)
{

  const unsigned char* in = input_buffer;
  size_t left;
  size_t fill;

  if( inlen > 0 )
  {
    left = state->buflen;
    fill = BLAKE2S_BLOCKBYTES - left;
    
    if( inlen > fill )
    {
      state->buflen = 0;
      memcpy( state->buf + left, in, fill ); /* Fill buffer */
      blake2s_increment_counter( state, BLAKE2S_BLOCKBYTES );
      F( state, state->buf ); /* Compress */
      in += fill; 
      inlen -= fill;

      while (inlen > BLAKE2S_BLOCKBYTES) {
        blake2s_increment_counter(state, BLAKE2S_BLOCKBYTES);
        F(state, in);
        in += BLAKE2S_BLOCKBYTES;
        inlen -= BLAKE2S_BLOCKBYTES;
    }
  }
  memcpy(state->buf + state->buflen, in, inlen);
  state->buflen += inlen;
  }
}

/**
 * Finalizes state, pads final block and stores hash
 *
 * @param      state  blake2s state instance
 * @param[in]  out    the output buffer
 * @param[in]  outlen the hash length
 */

void blake2s_final(blake2s_state* state, void* out, size_t outlen)
{
  uint8_t buffer[BLAKE2S_OUTBYTES] = { 0 };
  size_t i;

  blake2s_increment_counter(state, state->buflen);
  
  state->f[0] = UINT32_MAX;
  memset(state->buf + state->buflen, 0, BLAKE2S_BLOCKBYTES - state->buflen);
  
  F(state, state->buf);
  for (i = 0; i < 8; ++i){
    store32(buffer + sizeof(state->h[i]) * i, state->h[i]);
  }

  memcpy(out, buffer, state->outlen);
}

/**
 * The main blake2s function
 *
 * @param      output  the hash output
 * @param[in]  outlen  the hash length
 * @param[in]  input   the message input
 * @param[in]  inlen   the message length
 * @param[in]  key     the key
 * @param[in]  keylen  the key length
 */

void blake2s(void* output, size_t outlen, const void* input, size_t inlen,
        const void* key, size_t keylen)
{
  blake2s_state state = {0};
   
  blake2s_init(&state, outlen, key, keylen);
  blake2s_update(&state, (const uint8_t*)input, inlen);
  blake2s_final(&state, output, outlen);
}