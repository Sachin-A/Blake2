#include "blake2b.h"
#include "utils.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define BUF_LENGTH 100

void
print_hex(const uint8_t* s)
{
  printf("hash : ");
  while (*s)
    printf("%02x", *s++);
  printf("\n");
}

int
main(int argc, char const* argv[])
{
  uint8_t buf[BUF_LENGTH] = "00";
  uint8_t hash[BLAKE2B_OUTBYTES];

  for (int i = 0; i < BUF_LENGTH; ++i) {
    blake2(hash, BLAKE2B_OUTBYTES, buf, i);
  }

  printf("input: %s\n", buf);
  print_hex(hash);

  return 0;
}
