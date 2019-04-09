#include "ref10_ge.h"

/*
r = p
*/

extern void REF10_ge_p3_to_p2(REF10_ge_p2 *r,const REF10_ge_p3 *p)
{
  REF10_fe_copy(r->X,p->X);
  REF10_fe_copy(r->Y,p->Y);
  REF10_fe_copy(r->Z,p->Z);
}
