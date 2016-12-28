#include "blake2b.h"
#include "blake2b_kat.h"
#include <stdio.h>
#include <string.h>

void
print_hex(const uint8_t* hash, char* string, int len)
{
  size_t i;

  i = 0;
  printf("%s: ", string);
  while (i++ < len) {
    printf("%02x ", *hash++);
  }
  printf("\n\n");
}

int
main(int argc, char const* argv[])
{

  uint8_t key[BLAKE2B_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  uint8_t hash[BLAKE2B_OUTBYTES];
  size_t i;

  /* keyed hashing not implemented yet */
  for (i = 0; i < BLAKE2B_KEYBYTES; ++i)
    key[i] = (uint8_t)i;

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i)
    buf[i] = (uint8_t)0;

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i)
    buf[i] = (uint8_t)i;

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    blake2b(hash, BLAKE2B_OUTBYTES, buf, i, key, 0);
    if (memcmp(hash, blake2b_kat[i], BLAKE2B_OUTBYTES)) {
      printf("%d\n", (int)i);
      printf("Failed\n\n");
      print_hex(buf, "buffer", i);
      print_hex(key, "key", 0);
      print_hex(hash, "output", BLAKE2B_OUTBYTES);
      print_hex(blake2b_kat[i], "expected", BLAKE2B_OUTBYTES);
      return -1;
    }
  }
  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    blake2b(hash, BLAKE2B_OUTBYTES, buf, i, key, BLAKE2B_KEYBYTES);
    if (memcmp(hash, blake2b_keyed_kat[i], BLAKE2B_OUTBYTES)) {
      printf("%d\n", (int)i);
      printf("Failed\n\n");
      print_hex(buf, "buffer", i);
      print_hex(key, "key", BLAKE2B_KEYBYTES);
      print_hex(hash, "output", BLAKE2B_OUTBYTES);
      print_hex(blake2b_keyed_kat[i], "expected", BLAKE2B_OUTBYTES);
      return -1;
    }
  }
  printf("Success\n");

  return 0;
}
