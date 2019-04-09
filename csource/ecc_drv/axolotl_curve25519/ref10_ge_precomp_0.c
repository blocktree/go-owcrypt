#include "ref10_ge.h"

void REF10_ge_precomp_0(REF10_ge_precomp *h)
{
  REF10_fe_1(h->yplusx);
  REF10_fe_1(h->yminusx);
  REF10_fe_0(h->xy2d);
}
