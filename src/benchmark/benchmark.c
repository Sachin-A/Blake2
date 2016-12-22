#include <blake2b.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRIALS 64
#define MAXLEN 4096

int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long inlen);

static int
cmp(const void* x, const void* y)
{
  return (int* const*)x - (int* const*)y;
}

#ifdef _WIN32
/*  Windows */
#include <intrin.h>
uint64_t
cpucycles()
{
  return __rdtsc();
}
#else
/*  Linux/GCC */
uint64_t
cpucycles()
{
  unsigned int lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}
#endif

void
bench()
{
  static unsigned char in[MAXLEN];
  static unsigned long median[MAXLEN + 1];
  int i, j;

  printf("#Median cycles per byte\n");
  printf("# k bytes, median cycles per byte for k bytes\n");
  for (j = 0; j <= MAXLEN; ++j) {
    uint64_t cycles[TRIALS + 1];

    for (i = 0; i <= TRIALS; ++i) {
      cycles[i] = cpucycles();
      crypto_hash(in, in, j);
    }

    for (i = 0; i < TRIALS; ++i)
      cycles[i] = cycles[i + 1] - cycles[i];

    qsort(cycles, TRIALS, sizeof(uint64_t), cmp);
    median[j] = cycles[TRIALS / 2];
  }
  /* bytes, median cycles*/
  for (j = 0; j <= MAXLEN; j += 8)
    printf("%5d, %7.2f\n", j, (double)median[j] / j);

  printf("#Median cycles per byte for 2048 byte input:\n");
  printf("#2048   %6lu   %7.2f\n", median[2048], (double)median[2048] / 2048.0);
  printf("#Median cycles per byte for 4096 byte input:\n");
  printf("#4096   %6lu   %7.2f\n", median[4096], (double)median[4096] / 4096.0);
  printf("#Median cycles per byte for long input:\n");
  printf("#long   %7.2f\n", (double)(median[4096] - median[2048]) / 2048.0);
}

int
main()
{
  bench();
  return 0;
}
