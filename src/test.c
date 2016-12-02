#include "blake2b.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define BUF_LENGTH 256

void
print_hex(const uint8_t* hash)
{
  size_t i;

  i=0;
  printf("hash  :");
  while (i++ < BLAKE2B_OUTBYTES) {
    printf("%02x ", *hash++);
  }
}

int
main(int argc, char const* argv[])
{

  char buf[] = "abc";
  char key[] = "";
  uint8_t hash[BLAKE2B_OUTBYTES];
  size_t buflen = strlen(buf);
  size_t keylen = strlen(key);
  size_t i;

  for (i = 0; i <= buflen; ++i) {
    blake2b(hash, BLAKE2B_OUTBYTES, buf, i, key, keylen);
  }

  printf("input :%s\n", buf);
  printf("key   :%s\n", key);
  print_hex(hash);

  return 0;
}
