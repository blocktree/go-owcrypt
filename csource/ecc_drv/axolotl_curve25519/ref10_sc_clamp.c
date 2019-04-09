#include "ref10_crypto_additions.h"

void REF10_sc_clamp(unsigned char* a)
{
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
}
