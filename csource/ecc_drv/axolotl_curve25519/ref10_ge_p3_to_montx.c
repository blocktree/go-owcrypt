#include "ref10_fe.h"
#include "ref10_crypto_additions.h"

void REF10_ge_p3_to_montx(REF10_fe u, const REF10_ge_p3 *ed)
{
  /* 
     u = (y + 1) / (1 - y)
     or
     u = (y + z) / (z - y)

     NOTE: y=1 is converted to u=0 since REF10_fe_invert is mod-exp
  */

  REF10_fe y_plus_one, one_minus_y, inv_one_minus_y;

  REF10_fe_add(y_plus_one, ed->Y, ed->Z);
  REF10_fe_sub(one_minus_y, ed->Z, ed->Y);  
  REF10_fe_invert(inv_one_minus_y, one_minus_y);
  REF10_fe_mul(u, y_plus_one, inv_one_minus_y);
}

