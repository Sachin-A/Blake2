#include "blake2b.h"
#include "utils.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief      Initializes blake2b_state
 *
 * @param      S     blake2b_struct nstance passed by reference
 */
void
blake2b_init(blake2b_state* S)
{
  size_t i;
  memset(S, 0, sizeof(blake2b_state));
  for (i = 0; i < 8; ++i)
    S->h[i] = blake2b_IV[i];
}

/**
 * @brief  The Mix function is called by the Compress function, and mixes two
 *         8-byte words from the message into the hash state
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
 * @brief      The Compress function, F, takes a full 128-byte chunk of the
 *             input message and mixes it into the ongoing state array:
 *
 *
 * @param      h     persistent state vector
 * @param      block 128-byte (16 word) chunk of message to compress
 * @param      t     Count of bytes that have been fed into the Compression
 * @param[in]  f     Indicates if this is the final round of compression
 *
 * @return     { description_of_the_return_value }
 */
static void
F(uint64_t h[], uint8_t block[BLAKE2B_BLOCKBYTES], uint64_t t[], uint64_t f[])
{
  size_t i, j;
  uint64_t v[16], m[16], s[16];

  for (i = 0; i < 16; ++i) {
    m[i] = load64(block + i * sizeof(m[i]));
  }

  for (i = 0; i < 8; ++i) {
    v[i] = h[i];
    v[i + 8] = blake2b_IV[i];
  }

  v[12] ^= t[0];
  v[13] ^= t[1];
  v[14] ^= f[0];
  v[15] ^= f[1];

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
    h[i] = h[i] ^ v[i] ^ v[i + 8];
  }
}

/**
 * @brief      The main blake2 algorithm
 *
 * @param      d     Message
 * @param[in]  ll    Input bytes
 * @param[in]  kk    Key bytes
 * @param[in]  nn    Hash bytes
 */
static uint64_t*
blake2(uint64_t d[], uint64_t ll, uint64_t kk, size_t nn)
{

  size_t i;
  uint64_t h[8], buff[nn], block[16];
  uint64_t dd = ceil((double)kk / (double)BLAKE2B_BLOCKBYTES) +
                ceil((double)ll / (double)BLAKE2B_BLOCKBYTES);
  uint64_t temp[dd * 2];

  memset(temp, 0, dd * 128);
  if (kk > 0)
    temp[0] = temp[0] ^ kk;
  memcpy(temp + 1, d, ll);

  for (i = 0; i < 8; i++)
    h[i] = blake2b_IV[i];

  h[0] = h[0] ^ 0x01010000 ^ (kk << 8) ^ nn;

  if (dd > 1)
    for (i = 0; i < dd - 1; i++) {
      memcpy(block, temp, BLAKE2B_BLOCKBYTES);
      *temp += (BLAKE2B_BLOCKBYTES / 8);
      F(h, block, (i + 1) * BLAKE2B_BLOCKBYTES, 0);
    }
  *temp += (BLAKE2B_BLOCKBYTES / 8);
  memcpy(block, temp, BLAKE2B_BLOCKBYTES);

  if (kk = 0) {
    F(h, block, ll, 1);
  } else {
    F(h, block, ll + BLAKE2B_BLOCKBYTES, 1);
  }

  memcpy(buff, h, nn);
  // return buff;
  // Can't return array from function in C
  // https://stackoverflow.com/questions/11656532/returning-an-array-using-c
}
