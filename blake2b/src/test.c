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

/**
 * The main blake2b function
 */
void
blake2b(void* output, size_t outlen, const void* input, size_t inlen,
        const void* key, size_t keylen)
{
  blake2b_state state = { 0 };

  blake2b_init(&state, outlen, key, keylen);
  blake2b_update(&state, (const uint8_t*)input, inlen);
  blake2b_final(&state, output, outlen);
}

int
main()
{
  uint8_t key[BLAKE2B_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  uint8_t hash[BLAKE2B_OUTBYTES];
  size_t i;

  /* Key of the form (i, i+1 ... i+63 where i=0) */
  for (i = 0; i < BLAKE2B_KEYBYTES; ++i) {
    key[i] = (uint8_t)i;
  }

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    buf[i] = (uint8_t)0;
  }
  /* Buffer of the form (i, i+1 ... i+255 where i=0) */
  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    buf[i] = (uint8_t)i;
  }

  /* Testing for unkeyed hashes against the test vectors */
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
  /* Testing for keyed hashes against the test vectors */
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
  /* All test vectors pass successfully */
  printf("Success\n");

  return 0;
}
