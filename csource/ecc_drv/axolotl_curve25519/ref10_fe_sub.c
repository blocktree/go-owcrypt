#include "ref10_fe.h"

/*
h = f - g
Can overlap h with f or g.

Preconditions:
   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

Postconditions:
   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
*/

void REF10_fe_sub(REF10_fe h,const REF10_fe f,const REF10_fe g)
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
  REF10_crypto_int32 g0 = g[0];
  REF10_crypto_int32 g1 = g[1];
  REF10_crypto_int32 g2 = g[2];
  REF10_crypto_int32 g3 = g[3];
  REF10_crypto_int32 g4 = g[4];
  REF10_crypto_int32 g5 = g[5];
  REF10_crypto_int32 g6 = g[6];
  REF10_crypto_int32 g7 = g[7];
  REF10_crypto_int32 g8 = g[8];
  REF10_crypto_int32 g9 = g[9];
  REF10_crypto_int32 h0 = f0 - g0;
  REF10_crypto_int32 h1 = f1 - g1;
  REF10_crypto_int32 h2 = f2 - g2;
  REF10_crypto_int32 h3 = f3 - g3;
  REF10_crypto_int32 h4 = f4 - g4;
  REF10_crypto_int32 h5 = f5 - g5;
  REF10_crypto_int32 h6 = f6 - g6;
  REF10_crypto_int32 h7 = f7 - g7;
  REF10_crypto_int32 h8 = f8 - g8;
  REF10_crypto_int32 h9 = f9 - g9;
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
