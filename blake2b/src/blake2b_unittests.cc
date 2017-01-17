#include "blake2b.c"
#include "blake2b.h"
#include "blake2b_kat.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>

extern "C" void blake2b(void* out, size_t outlen, const void* in, size_t inlen,
            const void* key, size_t keylen);

::testing::AssertionResult CompareArray(uint8_t* hash, uint8_t* correct) {
  for (size_t i = 0; i < BLAKE2B_OUTBYTES; ++i) {
    if (hash[i] != correct[i]) {
      return ::testing::AssertionFailure() << "Hash[" << i << "] (" << hash[i]
      << ") != Correct[" << i << "] (" <<correct[i] << ")"; 
    }
    return ::testing::AssertionSuccess();
  }
}

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

TEST_F(KnownAnswerTests, Unkeyed) {
  for (size_t i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    blake2b(values->hash, BLAKE2B_OUTBYTES, values->buf, i, values->key, 0);
    memcpy(values->correct, blake2b_kat[i], BLAKE2B_OUTBYTES);

    EXPECT_TRUE(CompareArray(values->hash, values->correct));
  }

}

TEST_F(KnownAnswerTests, Keyed) {
  for (size_t i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    blake2b(values->hash, BLAKE2B_OUTBYTES, values->buf, i, values->key, BLAKE2B_OUTBYTES);
    memcpy(values->correct, blake2b_keyed_kat[i], BLAKE2B_OUTBYTES);
    
    EXPECT_TRUE(CompareArray(values->hash, values->correct));
  }

}

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
