#include "ref10_fe.h"

/*
h = f
*/

void REF10_fe_copy(REF10_fe h,const REF10_fe f)
{
  REF10_crypto_int32 f0 = f[0];
  REF10_crypto_int32 f1 = f[1];
  REF10_crypto_int32 f2 = f[2];
  REF10_crypto_int32 f3 = f[3];
  REF10_crypto_int32 f4 = f[4];
  REF10_crypto_int32 f5 = f[5];
  REF10_crypto_int32 f6 = f[6];
  REF10_crypto_int32 f7 = f[7];
  REF10_crypto_int32 f8 = f[8];
  REF10_crypto_int32 f9 = f[9];
  h[0] = f0;
  h[1] = f1;
  h[2] = f2;
  h[3] = f3;
  h[4] = f4;
  h[5] = f5;
  h[6] = f6;
  h[7] = f7;
  h[8] = f8;
  h[9] = f9;
}
