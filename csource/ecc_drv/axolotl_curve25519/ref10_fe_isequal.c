#include "ref10_fe.h"
#include "ref10_crypto_verify_32.h"

/*
return 1 if f == g
return 0 if f != g
*/

int REF10_fe_isequal(const REF10_fe f, const REF10_fe g)
{
  REF10_fe h;
  REF10_fe_sub(h, f, g);
  return 1 ^ (1 & (REF10_fe_isnonzero(h) >> 8));
}
