#include "blake2b.h"
#include <stdint.h>
#include <stdio.h>

/**
 * The BLAKE2b initialization vectors
 */
static const uint64_t blake2b_IV[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
  0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

/**
 * Table of permutations
 */
static const uint8_t blake2b_sigma[12][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

/**
 * @brief      Helper function to perform rotation in a 64 bit int
 *
 * @param[in]  w     original word
 * @param[in]  c     offset to rotate by
 *
 * @return     The rotated result
 */
static uint64_t
rotr64(const uint64_t w, const unsigned c)
{
  return (w >> c) | (w << (64 - c));
}

/**
 * @brief  The Mix function is called by the Compress function, and mixes two
 *         8-byte words from the message into the hash state
 *
 * @param   v           the work vector V
 * @params  a, b, c, d  indices to 8-byte word entries from the work vector V
 * @params  x, y        two 8-byte word entries from padded message v
 */
void
G(int64_t v[16], int a, int b, int c, int d, int64_t x, int64_t y)
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
 * @param      m     128-byte (16 word) chunk of message to compress
 * @param      t     Count of bytes that have been fed into the Compression
 * @param[in]  f     Indicates if this is the final round of compression
 *
 * @return     { description_of_the_return_value }
 */
static uint64_t*
F(uint64_t h[], uint64_t m[], uint64_t t[], uint64_t f)
{
  int i, j;
  uint64_t v[16], s[16];

  for (i = 0; i < 8; ++i) {
    v[i] = h[i];
    v[i + 8] = blake2b_IV[i];
  }

  v[12] = v[12] ^ t[0];
  v[13] = v[13] ^ t[1];

  if (f)
    v[14] = ~v[14];

  for (i = 0; i < 12; i++) {
    for (j = 0; j < 16; j++) {
      s[j] = blake2b_sigma[i % 10][j];
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
  return h;
}

/**
 * @brief      The main blake2 algorithm
 *
 * @param      d     Message
 * @param[in]  ll    Input bytes
 * @param[in]  kk    Key bytes
 * @param[in]  nn    Hash bytes
 */
static void
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
  // sizeof(d) will give size of pointer, not array
  memcpy(temp + 1, d, sizeof(d));

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
  return buff;
}
