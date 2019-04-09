#include "ref10_crypto_additions.h"
#include "ref10_ge.h"

/*
return 8 * p
*/

void REF10_ge_scalarmult_cofactor(REF10_ge_p3 *q, const REF10_ge_p3 *p)
{
  REF10_ge_p1p1 p1p1;
  REF10_ge_p2 p2;

  REF10_ge_p3_dbl(&p1p1, p);
  REF10_ge_p1p1_to_p2(&p2, &p1p1);

  REF10_ge_p2_dbl(&p1p1, &p2);
  REF10_ge_p1p1_to_p2(&p2, &p1p1);

  REF10_ge_p2_dbl(&p1p1, &p2);
  REF10_ge_p1p1_to_p3(q, &p1p1);
}
