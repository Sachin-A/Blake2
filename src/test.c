/* 
	A simple Blake2s implementation.

	Authors : Venkkatesh Sekar , Suhith Rajesh

	Standards : RFC 7693 / Nov 2015

*/

#include "blake2s.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BUF_LENGTH 256

void print_hex(const uint8_t* hash)
{ 
  size_t i;
  i = 0;
  printf("hash  : ");
  while (i++ < BLAKE2S_OUTBYTES)
    printf("%02x ", *hash++);
  printf("\n");
}

int main(int argc, char const* argv[])
{

  char buf[] = {};
 
  char key[] = {0x00, 0x01, 0x02, 0x03, 
                  0x04, 0x05, 0x06, 0x07, 
                  0x08, 0x09, 0x0a, 0x0b, 
                  0x0c, 0x0d, 0x0e, 0x0f, 
                  0x10, 0x11, 0x12, 0x13, 
                  0x14, 0x15, 0x16, 0x17, 
                  0x18, 0x19, 0x1a, 0x1b, 
                  0x1c, 0x1d, 0x1e, 0x1f};

  uint8_t hash[BLAKE2S_OUTBYTES];
  size_t buflen = sizeof(buf); 
  size_t keylen = sizeof(key); 
  size_t i;

  printf("input : %s\n", buf);
  printf("key   : %s\n", key);
  
  clock_t start = clock();
  for (i = 0; i <= buflen; ++i) {
    blake2s(hash, BLAKE2S_OUTBYTES, buf, i, key, keylen);
  }
  clock_t stop = clock();
  
  print_hex(hash);
  printf("time  : %f\n", (double)(stop - start) / CLOCKS_PER_SEC);
  return 0;
}
