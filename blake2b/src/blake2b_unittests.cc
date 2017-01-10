#include "blake2b.c"
#include "blake2b.h"
#include "blake2b_kat.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>

struct testvalues {
public:
  uint8_t key[BLAKE2B_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  uint8_t hash[BLAKE2B_OUTBYTES];
  uint8_t correct[BLAKE2B_OUTBYTES];
};

int main(int argc, char **argv) {

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
