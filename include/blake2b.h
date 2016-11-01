#ifndef BLAKE_H
#define BLAKE_H

#include <stddef.h>
#include <stdint.h>

enum blake2b_constant
{
  BLAKE2B_BLOCKBYTES = 128,
  BLAKE2B_OUTBYTES = 64,
  BLAKE2B_KEYBYTES = 64,
  BLAKE2B_PERSONALBYTES = 16
};

typedef struct blake2b_state
{
  uint64_t h[8];                   // Chained state
  uint64_t t[2];                   // total number of bytes
  uint64_t f[2];		   // last block flag
  uint8_t buf[BLAKE2B_BLOCKBYTES]; // input buffer
  size_t buflen;                   // size of buffer
  size_t outlen;                   // digest size
} blake2b_state;

int blake2b_init(blake2b_state *S, size_t outlen);
int blake2b_init_key( blake2b_state *S, size_t outlen, const void *key, size_t keylen );
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen);
static uint64_t*
F( uint64_t h[], uint64_t m[], uint64_t t[], uint64_t f );

#endif
