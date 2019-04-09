#include "ref10_fe.h"

/*
return 1 if f is in {1,3,5,...,q-2}
return 0 if f is in {0,2,4,...,q-1}

Preconditions:
   |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

int REF10_fe_isnegative(const REF10_fe f)
{
  unsigned char s[32];
  REF10_fe_tobytes(s,f);
  return s[0] & 1;
}
