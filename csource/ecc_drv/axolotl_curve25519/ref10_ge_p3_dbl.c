#include "ref10_ge.h"

/*
r = 2 * p
*/

void REF10_ge_p3_dbl(REF10_ge_p1p1 *r,const REF10_ge_p3 *p)
{
  REF10_ge_p2 q;
  REF10_ge_p3_to_p2(&q,p);
  REF10_ge_p2_dbl(r,&q);
}
