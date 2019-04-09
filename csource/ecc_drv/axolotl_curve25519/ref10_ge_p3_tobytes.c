#include "ref10_ge.h"

void REF10_ge_p3_tobytes(unsigned char *s,const REF10_ge_p3 *h)
{
  REF10_fe recip;
  REF10_fe x;
  REF10_fe y;

  REF10_fe_invert(recip,h->Z);
  REF10_fe_mul(x,h->X,recip);
  REF10_fe_mul(y,h->Y,recip);
  REF10_fe_tobytes(s,y);
  s[31] ^= REF10_fe_isnegative(x) << 7;
}
