#include<string.h>
#include "ref10_fe.h"
#include "ref10_crypto_additions.h"

int REF10_point_isreduced(const unsigned char* p)
{
  unsigned char strict[32];
 
  memmove(strict, p, 32);
  strict[31] &= 0x7F; /* mask off sign bit */
  return REF10_fe_isreduced(strict);
}
