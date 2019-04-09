#include "ref10_crypto_additions.h"
#include "ref10_ge.h"

/*
return 1 if p is the neutral point
return 0 otherwise
*/

int REF10_ge_isneutral(const REF10_ge_p3 *p)
{
  REF10_fe zero;
  REF10_fe_0(zero);

  /* Check if p == neutral element == (0, 1) */
  return (REF10_fe_isequal(p->X, zero) & REF10_fe_isequal(p->Y, p->Z));
}
