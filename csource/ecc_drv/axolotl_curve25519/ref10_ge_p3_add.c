#include "ref10_ge.h"

/*
r = p + q
*/

void REF10_ge_p3_add(REF10_ge_p3 *r, const REF10_ge_p3 *p, const REF10_ge_p3 *q)
{
  REF10_ge_cached p_cached;
  REF10_ge_p1p1 r_p1p1;

  REF10_ge_p3_to_cached(&p_cached, p);
  REF10_ge_add(&r_p1p1, q, &p_cached);
  REF10_ge_p1p1_to_p3(r, &r_p1p1);
}
