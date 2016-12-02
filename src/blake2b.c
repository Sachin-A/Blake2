#include "blake2b.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * Helper function to perform rotation in a 64 bit int
 *
 * @param[in]  w     original word
 * @param[in]  c     offset to rotate by
 *
 * @return     The rotated result
 */
uint64_t
rotr64(const uint64_t w, const unsigned c)
{
  return (w >> c) | (w << (64 - c));
}

/**
 * Loads into src 64 bytes at a time
 *
 * @param[in]  src   The source
 *
 * @return     { description_of_the_return_value }
 */
uint64_t
load64(const void* src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t* p = (const uint8_t*)src;
  return ((uint64_t)(p[0]) << 0) | ((uint64_t)(p[1]) << 8) |
         ((uint64_t)(p[2]) << 16) | ((uint64_t)(p[3]) << 24) |
         ((uint64_t)(p[4]) << 32) | ((uint64_t)(p[5]) << 40) |
         ((uint64_t)(p[6]) << 48) | ((uint64_t)(p[7]) << 56);
#endif
}

/**
 * Stores w into dst
 *
 * @param      dst   The destination
 * @param[in]  w     word to be stored
 */
void
store64(void* dst, uint64_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t* p = (uint8_t*)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
  p[4] = (uint8_t)(w >> 32);
  p[5] = (uint8_t)(w >> 40);
  p[6] = (uint8_t)(w >> 48);
  p[7] = (uint8_t)(w >> 56);
#endif
}

void
store32(void* dst, uint32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t* p = (uint8_t*)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}

/**
 * Increments the blake2b state counter
 *
 * @param      S     blake2b_state instance
 * @param[in]  inc   The increment
 */
void
blake2b_increment_counter(blake2b_state* S, const uint64_t inc)
{
  S->t[0] += inc;
  S->t[1] += (S->t[0] < inc);
}

/**
 * The Mix function is called by the Compress function, and mixes two 8-byte 
 * words from the message into the hash state
 *
 * @param   v           the work vector V
 * @params  a, b, c, d  indices to 8-byte word entries from the work vector V
 * @params  x, y        two 8-byte word entries from padded message v
 */
static void
G(uint64_t v[16], int a, int b, int c, int d, int64_t x, int64_t y)
{
  v[a] = v[a] + v[b] + x;
  v[d] = rotr64(v[d] ^ v[a], 32);

  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 24);

  v[a] = v[a] + v[b] + y;
  v[d] = rotr64(v[d] ^ v[a], 16);

  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 63);
}

/**
 * The blake2b compress function which takes a full 128-byte chunk of the 
 * input message and mixes it into the ongoing state array
 *
 * @param      state      blake2b_state instance
 * @param      block  The input block
 */
static void
F(blake2b_state* state, uint8_t block[BLAKE2B_BLOCKBYTES])
{
  size_t i, j;
  uint64_t v[16], m[16], s[16];

  for (i = 0; i < 16; ++i) {
    m[i] = load64(block + i * sizeof(m[i]));
  }

  for (i = 0; i < 8; ++i) {
    v[i] = state->h[i];
    v[i + 8] = blake2b_IV[i];
  }

  v[12] ^= state->t[0];
  v[13] ^= state->t[1];
  v[14] ^= state->f[0];
  v[15] ^= state->f[1];

  for (i = 0; i < 12; i++) {
    for (j = 0; j < 16; j++) {
      s[j] = blake2b_sigma[i][j];
    }
    G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }

  for (i = 0; i < 8; i++) {
    state->h[i] = state->h[i] ^ v[i] ^ v[i + 8];
  }
}

/**
 * Initializes blake2b state
 *
 * @param      state       blake2b_state instance passed by reference
 * @param[in]  outlen  The hash output length
 *
 * @return     sanity value
 */
int
blake2b_init(blake2b_state* state, size_t outlen, const void* key, size_t keylen)
{
  blake2b_param P[1];
  const uint8_t* p;
  size_t i;

  P->digest_length = (uint8_t)outlen;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  store32(&P->leaf_length, 0);
  store64(&P->node_offset, 0);
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->reserved, 0, sizeof(P->reserved));
  memset(P->salt, 0, sizeof(P->salt));
  memset(P->personal, 0, sizeof(P->personal));

  p = (const uint8_t*)(P);
  memset(state, 0, sizeof(blake2b_state));
  for (i = 0; i < 8; ++i) {
    state->h[i] = blake2b_IV[i];
  }
  for (i = 0; i < 8; ++i) {
    state->h[i] ^= load64(p + sizeof(state->h[i]) * i);
  }
  state->outlen = P->digest_length;

  if (keylen > 0) {
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset(block, 0, BLAKE2B_BLOCKBYTES);
    memcpy(block, key, keylen);
    blake2b_update(state, block, BLAKE2B_BLOCKBYTES);
  }
  return 0;
}

/**
 * Updates blake2b state
 *
 * @param      state      blake2b state instance
 * @param[in]  input_buffer    The input buffer
 * @param[in]  inlen  The input lenth
 *
 * @return     error code
 */
int
blake2b_update(blake2b_state* state, const void* input_buffer, size_t inlen)
{
  unsigned char* in;

  in = (unsigned char*)input_buffer;

  while (inlen > BLAKE2B_BLOCKBYTES) {
    blake2b_increment_counter(state, BLAKE2B_BLOCKBYTES);
    F(state, in);
    in += BLAKE2B_BLOCKBYTES;
    inlen -= BLAKE2B_BLOCKBYTES;
  }
  memcpy(state->buf + state->buflen, in, inlen);
  state->buflen += inlen;
  return 0;
}

int
blake2b_final(blake2b_state* state, void* out, size_t outlen)
{

  uint8_t buffer[BLAKE2B_OUTBYTES] = { 0 };
  size_t i;
  blake2b_increment_counter(state, state->buflen);

  /* set last chunk = true */
  state->f[0] = (uint64_t)-1;
  
  /* padding */
  memset(state->buf + state->buflen, 0, BLAKE2B_BLOCKBYTES - state->buflen);
  F(state, state->buf);

  /* Store back in little endian */
  for (i = 0; i < 8; ++i) {
    store64(buffer + sizeof(state->h[i]) * i, state->h[i]);
  }

  /* Copy first outlen bytes nto output buffer*/
  memcpy(out, buffer, state->outlen);
  return 0;
}

/**
 * The main blake2b function
 *
 * @param      output  The hash output
 * @param[in]  outlen  The hash length
 * @param[in]  input   The message input
 * @param[in]  inlen   The message length
 * @param[in]  key     The key
 * @param[in]  keylen  The key length
 *
 * @return     sanity value
 */
int
blake2b(void* output, size_t outlen, const void* input, size_t inlen,
        const void* key, size_t keylen)
{
  blake2b_state state[1];

  if (blake2b_init(state, outlen, key, keylen) < 0) {
    return -1;
  }
  if (blake2b_update(state, (const uint8_t*)input, inlen) < 0) {
    return -1;
  }
  if (blake2b_final(state, output, outlen) < 0) {
    return -1;
  }
  return 0;
}
