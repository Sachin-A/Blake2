#include "blake2b.h"
#include <inttypes.h>
#include <stdio.h>

#define BUF_LENGTH 100

int
main(void)
{
  uint8_t buf[BUF_LENGTH] = "";

  for (int i = 0; buf[i] != 0; i++)
    printf("%" PRId8 "\n", buf[i]);

  uint8_t hash[BLAKE2B_OUTBYTES];

  // for (i = 0; i < BUF_LENGTH; ++i)
  //   buf[i] = (uint8_t)i;

  for (int i = 0; i < BUF_LENGTH; ++i) {
    blake2(hash, BLAKE2B_OUTBYTES, buf, i);
  }

  for (int i = 0; i < BLAKE2B_OUTBYTES; i++)
    printf("%" PRId8 "\n", hash[i]);

  return 0;
}
