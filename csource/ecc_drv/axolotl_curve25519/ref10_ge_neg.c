#include "ref10_crypto_additions.h"
#include "ref10_ge.h"

/*
return r = -p
*/


void REF10_ge_neg(REF10_ge_p3* r, const REF10_ge_p3 *p)
{
  REF10_fe_neg(r->X, p->X);
  REF10_fe_copy(r->Y, p->Y);
  REF10_fe_copy(r->Z, p->Z);
  REF10_fe_neg(r->T, p->T);
}
