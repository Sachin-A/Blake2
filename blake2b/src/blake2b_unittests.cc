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

class KnownAnswerTests : public ::testing::Test {
public:
  virtual void SetUp() {
    values = new testvalues();
    size_t i;
    /* Key of the form (i, i+1 ... i+63 where i=0) */
    for (i = 0; i < BLAKE2B_KEYBYTES; ++i) {
      values->key[i] = (uint8_t)i;
    }

    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      values->buf[i] = (uint8_t)0;
    }
    /* Buffer of the form (i, i+1 ... i+255 where i=0) */
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      values->buf[i] = (uint8_t)i;
    }
  }

  virtual void TearDown() {
    delete values;  
  }
  testvalues *values;
};

int main(int argc, char **argv) {

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
