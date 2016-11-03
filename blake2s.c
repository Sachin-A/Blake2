/* 
	A simple Blake2s implementation.

	Authors : Venkkatesh Sekar , Suhith Rajesh

	Standards : RFC 7693 / Nov 2015

*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "blake2.h"

static const uint32_t blake2s_IV[8] =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t blake2s_sigma[10][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

static uint64_t rotr32(const uint64_t w, const unsigned c)
{
  return (w >> c) | (w << (32 - c));
}

/*
 FUNCTION G( v[0..15], a, b, c, d, x, y )
       |
       |   v[a] := (v[a] + v[b] + x) mod 2**w
       |   v[d] := (v[d] ^ v[a]) >>> R1
       |   v[c] := (v[c] + v[d])     mod 2**w
       |   v[b] := (v[b] ^ v[c]) >>> R2
       |   v[a] := (v[a] + v[b] + y) mod 2**w
       |   v[d] := (v[d] ^ v[a]) >>> R3
       |   v[c] := (v[c] + v[d])     mod 2**w
       |   v[b] := (v[b] ^ v[c]) >>> R4
       |
       |   RETURN v[0..15]
       |
       END FUNCTION.
*/


void G(int64_t v[16], int a, int b,int c,int d, int64_t x, int64_t y) {                      
 
  do {                                    
    v[a] = v[a] + v[b] + x;
    v[d] = rotr32(v[d] ^ v[a] , 16);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c] , 12);

    v[a] = v[a] + v[b] + y;
    v[d] = rotr32(v[d] ^ v[a] , 8);
    v[c] = v[c] + v[d];
    v[b] = rot32(v[b] ^ v[c] , 7);         
  } while(0)

}
/*     FUNCTION F( h[0..7], m[0..15], t, f )
       |
       |      // Initialize local work vector v[0..15]
       |      v[0..7] := h[0..7]              // First half from state.
       |      v[8..15] := IV[0..7]            // Second half from IV.
       |
       |      v[12] := v[12] ^ (t mod 2**w)   // Low word of the offset.
       |      v[13] := v[13] ^ (t >> w)       // High word.
       |
       |      IF f = TRUE THEN                // last block flag?
       |      |   v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
       |      END IF.
       |
       |      // Cryptographic mixing
       |      FOR i = 0 TO r - 1 DO           // Ten or twelve rounds.
       |      |
       |      |   // Message word selection permutation for this round.
       |      |   s[0..15] := SIGMA[i mod 10][0..15]
       |      |
       |      |   v := G( v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]] )
       |      |   v := G( v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]] )
       |      |   v := G( v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]] )
       |      |   v := G( v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]] )
       |      |
       |      |   v := G( v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]] )
       |      |   v := G( v, 1, 6, 11, 12, m[s[10]], m[s[11]] )
       |      |   v := G( v, 2, 7,  8, 13, m[s[12]], m[s[13]] )
       |      |   v := G( v, 3, 4,  9, 14, m[s[14]], m[s[15]] )
       |      |
       |      END FOR
       |
       |      FOR i = 0 TO 7 DO               // XOR the two halves.
       |      |   h[i] := h[i] ^ v[i] ^ v[i + 8]
       |      END FOR.
       |
       |      RETURN h[0..7]                  // New state.
       |
       END FUNCTION.
  */

static uint64_t* F(uint64_t h[], uint64_t m[], uint64_t t[], uint64_t f)
{
  int i, j;
  uint64_t v[16], s[16];

  for (i = 0; i < 8; ++i) {
    v[i] = h[i];
    v[i + 8] = blake2s_IV[i];
  }

  v[12] = v[12] ^ t[0];
  v[13] = v[13] ^ t[1];

  if (f)
    v[14] = ~v[14];

  for (i = 0; i < 12; i++) {
    for (j = 0; j < 16; j++) {
      s[j] = blake2s_sigma[i % 10][j];
    }
    G(v, 0, 4, 8,  12, m[s[0]],  m[s[1]]);
    G(v, 1, 5, 9,  13, m[s[2]],  m[s[3]]);
    G(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
    G(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
    G(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
    G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    G(v, 2, 7, 8,  13, m[s[12]], m[s[13]]);
    G(v, 3, 4, 9,  14, m[s[14]], m[s[15]]);
  }

  for (i = 0; i < 8; i++) {
    h[i] = h[i] ^ v[i] ^ v[i + 8];
  }
  return h;
}

/*
    FUNCTION BLAKE2( d[0..dd-1], ll, kk, nn )
        |
        |     h[0..7] := IV[0..7]          // Initialization Vector.
        |
        |     // Parameter block p[0]
        |     h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn
        |
        |     // Process padded key and data blocks
        |     IF dd > 1 THEN
        |     |       FOR i = 0 TO dd - 2 DO
        |     |       |       h := F( h, d[i], (i + 1) * bb, FALSE )
        |     |       END FOR.
        |     END IF.
        |
        |     // Final block.
        |     IF kk = 0 THEN
        |     |       h := F( h, d[dd - 1], ll, TRUE )
        |     ELSE
        |     |       h := F( h, d[dd - 1], ll + bb, TRUE )
        |     END IF.
        |
        |     RETURN first "nn" bytes from little-endian word array h[].
        |
        END FUNCTION.

*/
