#include "ref10_ge.h"

void REF10_ge_p3_0(REF10_ge_p3 *h)
{
  REF10_fe_0(h->X);
  REF10_fe_1(h->Y);
  REF10_fe_1(h->Z);
  REF10_fe_0(h->T);
}
