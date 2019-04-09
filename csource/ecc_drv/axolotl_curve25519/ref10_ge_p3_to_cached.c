#include "ref10_ge.h"
/*
r = p
*/

static const REF10_fe REF10_d2 = {
    -21827239,-5839606,-30745221,13898782,229458,15978800,-12551817,-6495438,29715968,9444199
};


extern void REF10_ge_p3_to_cached(REF10_ge_cached *r,const REF10_ge_p3 *p)
{
  REF10_fe_add(r->YplusX,p->Y,p->X);
  REF10_fe_sub(r->YminusX,p->Y,p->X);
  REF10_fe_copy(r->Z,p->Z);
  REF10_fe_mul(r->T2d,p->T,REF10_d2);
}
