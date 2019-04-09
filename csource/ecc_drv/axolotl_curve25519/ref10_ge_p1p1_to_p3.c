#include "ref10_ge.h"

/*
r = p
*/

extern void REF10_ge_p1p1_to_p3(REF10_ge_p3 *r,const REF10_ge_p1p1 *p)
{
  REF10_fe_mul(r->X,p->X,p->T);
  REF10_fe_mul(r->Y,p->Y,p->Z);
  REF10_fe_mul(r->Z,p->Z,p->T);
  REF10_fe_mul(r->T,p->X,p->Y);
}
