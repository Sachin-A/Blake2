#include "blake2b.h"
#include <stdio.h>
#include <string.h>

#define BUF_LENGTH 256

void
print_hex(const uint8_t* hash, char* string, int len)
{
  size_t i;

  i = 0;
  printf("%s: ", string);
  while (i++ < len) {
    printf("%02x ", *hash++);
  }
  printf("\n");
}

int
main(int argc, char const* argv[])
{

  uint8_t key[BLAKE2B_KEYBYTES];
  uint8_t buf[BUF_LENGTH];
  uint8_t hash[BLAKE2B_OUTBYTES];
  size_t i, offset;

  // keyed hashing not implemented yet
  for (i = 0; i < BLAKE2B_KEYBYTES; ++i)
    key[i] = (uint8_t)i;

  offset = 256;

  for (i = 0; i < offset; ++i)
    buf[i] = (uint8_t)i;

  for (i = offset; i < BUF_LENGTH; ++i)
    buf[i] = (uint8_t)0;

  /* Test simple API */
  for (i = 0; i < offset; ++i) {
    blake2b(hash, BLAKE2B_OUTBYTES, buf, i, key, BLAKE2B_KEYBYTES);
  }

  print_hex(buf, "buffer", offset);
  print_hex(key, "key", 0);
  print_hex(hash, "hash", BLAKE2B_OUTBYTES);

  return 0;
}
