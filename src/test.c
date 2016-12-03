/* 
	A simple Blake2s implementation.

	Authors : Venkkatesh Sekar , Suhith Rajesh

	Standards : RFC 7693 / Nov 2015

*/

#include "blake2s.h"
#include "utils.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define BUF_LENGTH 256

void
print_hex(const uint8_t* s)
{
  printf("hash  :");
  while (*s)
    printf("%02x", *s++);
  printf("\n");
}

int
main(int argc, char const* argv[])
{

  uint8_t buf[] = "";
  uint8_t key[] = "";
  uint8_t hash[BLAKE2S_OUTBYTES];
  size_t buflen = strlen((char *)buf);
  size_t keylen = strlen((char *)key);
  size_t i;

  for (i = 0; i <= buflen; ++i) {
    blake2s(hash, BLAKE2S_OUTBYTES, buf, i, key, keylen);
  }

  printf("input :%s\n", buf);
  printf("key   :%s\n", key);
  print_hex(hash);

  return 0;
}

