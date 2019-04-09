#include "ref10_fe.h"

/*
h = -f

Preconditions:
   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

Postconditions:
   |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
*/

void REF10_fe_neg(REF10_fe h,const REF10_fe f)
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
  REF10_crypto_int32 h0 = -f0;
  REF10_crypto_int32 h1 = -f1;
  REF10_crypto_int32 h2 = -f2;
  REF10_crypto_int32 h3 = -f3;
  REF10_crypto_int32 h4 = -f4;
  REF10_crypto_int32 h5 = -f5;
  REF10_crypto_int32 h6 = -f6;
  REF10_crypto_int32 h7 = -f7;
  REF10_crypto_int32 h8 = -f8;
  REF10_crypto_int32 h9 = -f9;
  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}
