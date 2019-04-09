#include "ref10_fe.h"
#include "ref10_crypto_verify_32.h"

int REF10_fe_isreduced(const unsigned char* s)
{
  REF10_fe f;
  unsigned char strict[32];

  REF10_fe_frombytes(f, s);
  REF10_fe_tobytes(strict, f);
  if (REF10_crypto_verify_32(strict, s) != 0)
    return 0;
  return 1;
}
