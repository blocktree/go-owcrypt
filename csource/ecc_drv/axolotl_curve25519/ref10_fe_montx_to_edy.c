
#include "ref10_fe.h"
#include "ref10_crypto_additions.h"

void REF10_fe_montx_to_edy(REF10_fe y, const REF10_fe u)
{
  /* 
     y = (u - 1) / (u + 1)

     NOTE: u=-1 is converted to y=0 since REF10_fe_invert is mod-exp
  */
  REF10_fe one, um1, up1;

  REF10_fe_1(one);
  REF10_fe_sub(um1, u, one);
  REF10_fe_add(up1, u, one);
  REF10_fe_invert(up1, up1);
  REF10_fe_mul(y, um1, up1);
}

void REF10_fe_montx_from_edy(REF10_fe u, const REF10_fe y)
{
    /*
     u = (1 + y) / (1 - y)
     
     NOTE: u=-1 is converted to y=0 since REF10_fe_invert is mod-exp
     */
    REF10_fe one, um1, up1;
    REF10_fe_1(one);
    REF10_fe_sub(um1, one, y);
    REF10_fe_invert(um1, um1);
    REF10_fe_add(up1, y, one);
    REF10_fe_mul(u, um1, up1);
}
