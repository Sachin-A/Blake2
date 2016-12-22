#include <openssl/md5.h>
#include <stddef.h>

int
crypto_hash(unsigned char* out, const unsigned char* in,
            unsigned long inlen)
{
  MD5(in, inlen, out);
  return 0;
}
