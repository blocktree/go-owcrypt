#include "ref10_fe.h"
#include "ref10_crypto_verify_32.h"

/*
return nonzero if f == 0
return 0 if f != 0

Preconditions:
   |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

/* TREVOR'S COMMENT 
 *
 * I think the above comment is wrong.  Instead:
 *
 * return 0 if f == 0
 * return -1 if f != 0 
 *
 * */

static const unsigned char REF10_zero[32];

int REF10_fe_isnonzero(const REF10_fe f)
{
  unsigned char s[32];
  REF10_fe_tobytes(s,f);
  return REF10_crypto_verify_32(s,REF10_zero);
}
