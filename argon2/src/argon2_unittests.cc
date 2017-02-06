#include <stdio.h>
#include <stdint.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <string.h>
#include "argon2.h"

#define OUT_LEN 32
#define ENCODED_LEN 108

extern "C"

::testing::AssertionResult CompareHash(char *hash, const char *correct) {
    if (memcmp(hash, correct, strlen(correct)) == 0) {
        return ::testing::AssertionSuccess();
    }
    else{
      return ::testing::AssertionFailure() << "Hash[](" << hash << ") != Correct[](" <<correct << ")" ; 
    }
    
}

::testing::AssertionResult VerifyRet(int ret) {
    if (ret == ARGON2_OK) {
        return ::testing::AssertionSuccess();
    }
    else{
        return ::testing::AssertionFailure();
    }
}

struct testvalues {
    public:

      const char *password[8] = {"password", "password", "password", "password",
                                "password", "password", "differentpassword", "password"};
      const char *salt[8] = {"somesalt", "somesalt", "somesalt", "somesalt",
                            "somesalt", "somesalt", "somesalt", "diffsalt" };

      const char *hexref[16] = {  "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
                            "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
                            "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
                            "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
                            "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
                            "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
                            "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
                            "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
                            "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
                            "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
                            "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
                            "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
                            "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
                            "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
                            "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
                            "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271"};
     const char *mcfref[16] = {
             "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ"
             "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
             "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ"
             "$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc",
             "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ"
             "$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY",             
             "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ"
             "$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs",
             "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ"
             "$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI",
             "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ"
             "$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs",
             "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ"
             "$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM",
             "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ"
             "$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc",
             "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ"
             "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
             "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ"
             "$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s",
             "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ"
             "$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8",
             "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ"
             "$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E",
             "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ"
             "$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8",
             "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ"
             "$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls",
             "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ"
             "$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4",
             "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ"
             "$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE"
         };

      int thread[8] = { 2 , 2 , 2 , 2 , 1 , 4 , 2 , 2};
      int m[8] = {16 , 18 , 8 , 8 , 16 , 16 , 16 , 16};
      int parallelism[8] = {1 , 1 , 1 , 2 , 1 , 1 , 1 , 1};
      unsigned char out[OUT_LEN];
      unsigned char hex_out[OUT_LEN * 2 + 4];
      char encoded[ENCODED_LEN];
};

class KnownAnswerTests : public ::testing::Test {
public:
  virtual void SetUp() {
    values = new testvalues(); 
  }

  virtual void TearDown() {
    delete values;  
  }

  testvalues *values;

};

TEST_F(KnownAnswerTests, Version1) {
    int version = ARGON2_VERSION_10;
    int ret;
    for(int i = 0 ; i < 8 ; i++){
    
        ret  = argon2_hash(values->thread[i], 1 << values->m[i], values->parallelism[i], values->password[i], 
                strlen(values -> password[i]), values->salt[i], strlen(values->salt[i]), 
                values->out, OUT_LEN, values->encoded, ENCODED_LEN, Argon2_i, version);
        
        EXPECT_TRUE(VerifyRet(ret));

        if (ARGON2_VERSION_NUMBER == version) {
            EXPECT_TRUE(CompareHash((char *)(intptr_t)values->encoded[i], values->mcfref[i]));
        }
        ret = argon2_verify(values->encoded, values->password[i] , strlen(values->password[i]), Argon2_i);
        EXPECT_TRUE(VerifyRet(ret));
        ret = argon2_verify(values->mcfref[i], values->password[i], strlen(values->password[i]), Argon2_i);
        EXPECT_TRUE(VerifyRet(ret));
    }
}

TEST_F(KnownAnswerTests, Version2) {
    int version =  ARGON2_VERSION_NUMBER;
    int ret;
    for(int i = 0 ; i < 8 ; i++){
    
        ret = argon2_hash(values->thread[i], 1 << values->m[i], values->parallelism[i], values->password[i], 
                strlen(values -> password[i]), values->salt[i], strlen(values->salt[i]), 
                values->out, OUT_LEN, values->encoded, ENCODED_LEN, Argon2_i, version);

        if (ARGON2_VERSION_NUMBER == version) {
            EXPECT_TRUE(CompareHash((char *)(intptr_t)values->encoded, values->mcfref[i+8]));
        }
        ret = argon2_verify(values->encoded, values->password[i] , strlen(values->password[i]), Argon2_i);
        EXPECT_TRUE(VerifyRet(ret));
        ret = argon2_verify(values->mcfref[i+8], values->password[i], strlen(values->password[i]), Argon2_i);
        EXPECT_TRUE(VerifyRet(ret));
    }
  }

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
