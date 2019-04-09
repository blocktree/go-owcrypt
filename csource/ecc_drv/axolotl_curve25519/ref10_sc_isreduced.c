#include <string.h>
#include "ref10_fe.h"
#include "ref10_sc.h"
#include "ref10_crypto_additions.h"
#include "ref10_crypto_verify_32.h"

int REF10_sc_isreduced(const unsigned char* s)
{
  unsigned char strict[64];

  memset(strict, 0, 64);
  memmove(strict, s, 32);
  REF10_sc_reduce(strict);
  if (REF10_crypto_verify_32(strict, s) != 0)
    return 0;
  return 1;
}
