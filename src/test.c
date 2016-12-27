/* 
	A simple Blake2s implementation.

	Authors : Venkkatesh Sekar , Suhith Rajesh

	Standards : RFC 7693 / Nov 2015

*/

#include "blake2s.h"
#include "blake2s_kat.h"
#include <stdio.h>
#include <string.h>

#define BUF_LENGTH 256

void print_hex(const uint8_t* hash, char* string, int len)
{ 
  size_t i;
  i = 0;
  printf("%s  : ", string);
  while (i++ < len)
    printf("%02x ", *hash++);
  printf("\n");
}

int main(int argc, char const* argv[])
{
  uint8_t key[BLAKE2S_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  uint8_t hash[BLAKE2S_OUTBYTES];
  size_t i;
  
  for (i = 0; i < BLAKE2S_KEYBYTES; ++i)
    key[i] = (uint8_t)i;

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i)
    buf[i] = (uint8_t)0;

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i)
    buf[i] = (uint8_t)i;

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    blake2s(hash, BLAKE2S_OUTBYTES, buf, i, key, BLAKE2S_KEYBYTES);

    if (memcmp(hash, blake2s_kat[i], BLAKE2S_OUTBYTES)) {
      printf("Part %d\n", (int)i);
      printf("FAILED\n");
      print_hex(buf, "buffer", i);
      print_hex(key, "key", 0);
      print_hex(hash, "output", BLAKE2S_OUTBYTES);
      print_hex(blake2s_kat[i], "expected", BLAKE2S_OUTBYTES);

      return -1;
    }
  }

  printf("SUCCESS\n");
  print_hex(blake2s_kat[i], "expected", BLAKE2S_OUTBYTES);

  return 0;
}
