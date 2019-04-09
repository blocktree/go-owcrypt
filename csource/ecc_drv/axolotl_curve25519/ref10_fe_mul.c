#include "ref10_fe.h"
#include "ref10_crypto_int64.h"

/*
h = f * g
Can overlap h with f or g.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
   |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

/*
Notes on implementation strategy:

Using schoolbook multiplication.
Karatsuba would save a little in some cost models.

Most multiplications by 2 and 19 are 32-bit precomputations;
cheaper than 64-bit postcomputations.

There is one remaining multiplication by 19 in the carry chain;
one *19 precomputation can be merged into this,
but the resulting data flow is considerably less clean.

There are 12 carries below.
10 of them are 2-way parallelizable and vectorizable.
Can get away with 11 carries, but then data flow is much deeper.

With tighter constraints on inputs can squeeze carries into int32.
*/

void REF10_fe_mul(REF10_fe h,const REF10_fe f,const REF10_fe g)
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
  REF10_crypto_int32 g1_19 = 19 * g1; /* 1.959375*2^29 */
  REF10_crypto_int32 g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
  REF10_crypto_int32 g3_19 = 19 * g3;
  REF10_crypto_int32 g4_19 = 19 * g4;
  REF10_crypto_int32 g5_19 = 19 * g5;
  REF10_crypto_int32 g6_19 = 19 * g6;
  REF10_crypto_int32 g7_19 = 19 * g7;
  REF10_crypto_int32 g8_19 = 19 * g8;
  REF10_crypto_int32 g9_19 = 19 * g9;
  REF10_crypto_int32 f1_2 = 2 * f1;
  REF10_crypto_int32 f3_2 = 2 * f3;
  REF10_crypto_int32 f5_2 = 2 * f5;
  REF10_crypto_int32 f7_2 = 2 * f7;
  REF10_crypto_int32 f9_2 = 2 * f9;
  REF10_crypto_int64 f0g0    = f0   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f0g1    = f0   * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f0g2    = f0   * (REF10_crypto_int64) g2;
  REF10_crypto_int64 f0g3    = f0   * (REF10_crypto_int64) g3;
  REF10_crypto_int64 f0g4    = f0   * (REF10_crypto_int64) g4;
  REF10_crypto_int64 f0g5    = f0   * (REF10_crypto_int64) g5;
  REF10_crypto_int64 f0g6    = f0   * (REF10_crypto_int64) g6;
  REF10_crypto_int64 f0g7    = f0   * (REF10_crypto_int64) g7;
  REF10_crypto_int64 f0g8    = f0   * (REF10_crypto_int64) g8;
  REF10_crypto_int64 f0g9    = f0   * (REF10_crypto_int64) g9;
  REF10_crypto_int64 f1g0    = f1   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f1g1_2  = f1_2 * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f1g2    = f1   * (REF10_crypto_int64) g2;
  REF10_crypto_int64 f1g3_2  = f1_2 * (REF10_crypto_int64) g3;
  REF10_crypto_int64 f1g4    = f1   * (REF10_crypto_int64) g4;
  REF10_crypto_int64 f1g5_2  = f1_2 * (REF10_crypto_int64) g5;
  REF10_crypto_int64 f1g6    = f1   * (REF10_crypto_int64) g6;
  REF10_crypto_int64 f1g7_2  = f1_2 * (REF10_crypto_int64) g7;
  REF10_crypto_int64 f1g8    = f1   * (REF10_crypto_int64) g8;
  REF10_crypto_int64 f1g9_38 = f1_2 * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 f2g0    = f2   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f2g1    = f2   * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f2g2    = f2   * (REF10_crypto_int64) g2;
  REF10_crypto_int64 f2g3    = f2   * (REF10_crypto_int64) g3;
  REF10_crypto_int64 f2g4    = f2   * (REF10_crypto_int64) g4;
  REF10_crypto_int64 f2g5    = f2   * (REF10_crypto_int64) g5;
  REF10_crypto_int64 f2g6    = f2   * (REF10_crypto_int64) g6;
  REF10_crypto_int64 f2g7    = f2   * (REF10_crypto_int64) g7;
  REF10_crypto_int64 f2g8_19 = f2   * (REF10_crypto_int64) g8_19;
  REF10_crypto_int64 f2g9_19 = f2   * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 f3g0    = f3   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f3g1_2  = f3_2 * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f3g2    = f3   * (REF10_crypto_int64) g2;
  REF10_crypto_int64 f3g3_2  = f3_2 * (REF10_crypto_int64) g3;
  REF10_crypto_int64 f3g4    = f3   * (REF10_crypto_int64) g4;
  REF10_crypto_int64 f3g5_2  = f3_2 * (REF10_crypto_int64) g5;
  REF10_crypto_int64 f3g6    = f3   * (REF10_crypto_int64) g6;
  REF10_crypto_int64 f3g7_38 = f3_2 * (REF10_crypto_int64) g7_19;
  REF10_crypto_int64 f3g8_19 = f3   * (REF10_crypto_int64) g8_19;
  REF10_crypto_int64 f3g9_38 = f3_2 * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 f4g0    = f4   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f4g1    = f4   * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f4g2    = f4   * (REF10_crypto_int64) g2;
  REF10_crypto_int64 f4g3    = f4   * (REF10_crypto_int64) g3;
  REF10_crypto_int64 f4g4    = f4   * (REF10_crypto_int64) g4;
  REF10_crypto_int64 f4g5    = f4   * (REF10_crypto_int64) g5;
  REF10_crypto_int64 f4g6_19 = f4   * (REF10_crypto_int64) g6_19;
  REF10_crypto_int64 f4g7_19 = f4   * (REF10_crypto_int64) g7_19;
  REF10_crypto_int64 f4g8_19 = f4   * (REF10_crypto_int64) g8_19;
  REF10_crypto_int64 f4g9_19 = f4   * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 f5g0    = f5   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f5g1_2  = f5_2 * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f5g2    = f5   * (REF10_crypto_int64) g2;
  REF10_crypto_int64 f5g3_2  = f5_2 * (REF10_crypto_int64) g3;
  REF10_crypto_int64 f5g4    = f5   * (REF10_crypto_int64) g4;
  REF10_crypto_int64 f5g5_38 = f5_2 * (REF10_crypto_int64) g5_19;
  REF10_crypto_int64 f5g6_19 = f5   * (REF10_crypto_int64) g6_19;
  REF10_crypto_int64 f5g7_38 = f5_2 * (REF10_crypto_int64) g7_19;
  REF10_crypto_int64 f5g8_19 = f5   * (REF10_crypto_int64) g8_19;
  REF10_crypto_int64 f5g9_38 = f5_2 * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 f6g0    = f6   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f6g1    = f6   * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f6g2    = f6   * (REF10_crypto_int64) g2;
  REF10_crypto_int64 f6g3    = f6   * (REF10_crypto_int64) g3;
  REF10_crypto_int64 f6g4_19 = f6   * (REF10_crypto_int64) g4_19;
  REF10_crypto_int64 f6g5_19 = f6   * (REF10_crypto_int64) g5_19;
  REF10_crypto_int64 f6g6_19 = f6   * (REF10_crypto_int64) g6_19;
  REF10_crypto_int64 f6g7_19 = f6   * (REF10_crypto_int64) g7_19;
  REF10_crypto_int64 f6g8_19 = f6   * (REF10_crypto_int64) g8_19;
  REF10_crypto_int64 f6g9_19 = f6   * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 f7g0    = f7   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f7g1_2  = f7_2 * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f7g2    = f7   * (REF10_crypto_int64) g2;
  REF10_crypto_int64 f7g3_38 = f7_2 * (REF10_crypto_int64) g3_19;
  REF10_crypto_int64 f7g4_19 = f7   * (REF10_crypto_int64) g4_19;
  REF10_crypto_int64 f7g5_38 = f7_2 * (REF10_crypto_int64) g5_19;
  REF10_crypto_int64 f7g6_19 = f7   * (REF10_crypto_int64) g6_19;
  REF10_crypto_int64 f7g7_38 = f7_2 * (REF10_crypto_int64) g7_19;
  REF10_crypto_int64 f7g8_19 = f7   * (REF10_crypto_int64) g8_19;
  REF10_crypto_int64 f7g9_38 = f7_2 * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 f8g0    = f8   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f8g1    = f8   * (REF10_crypto_int64) g1;
  REF10_crypto_int64 f8g2_19 = f8   * (REF10_crypto_int64) g2_19;
  REF10_crypto_int64 f8g3_19 = f8   * (REF10_crypto_int64) g3_19;
  REF10_crypto_int64 f8g4_19 = f8   * (REF10_crypto_int64) g4_19;
  REF10_crypto_int64 f8g5_19 = f8   * (REF10_crypto_int64) g5_19;
  REF10_crypto_int64 f8g6_19 = f8   * (REF10_crypto_int64) g6_19;
  REF10_crypto_int64 f8g7_19 = f8   * (REF10_crypto_int64) g7_19;
  REF10_crypto_int64 f8g8_19 = f8   * (REF10_crypto_int64) g8_19;
  REF10_crypto_int64 f8g9_19 = f8   * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 f9g0    = f9   * (REF10_crypto_int64) g0;
  REF10_crypto_int64 f9g1_38 = f9_2 * (REF10_crypto_int64) g1_19;
  REF10_crypto_int64 f9g2_19 = f9   * (REF10_crypto_int64) g2_19;
  REF10_crypto_int64 f9g3_38 = f9_2 * (REF10_crypto_int64) g3_19;
  REF10_crypto_int64 f9g4_19 = f9   * (REF10_crypto_int64) g4_19;
  REF10_crypto_int64 f9g5_38 = f9_2 * (REF10_crypto_int64) g5_19;
  REF10_crypto_int64 f9g6_19 = f9   * (REF10_crypto_int64) g6_19;
  REF10_crypto_int64 f9g7_38 = f9_2 * (REF10_crypto_int64) g7_19;
  REF10_crypto_int64 f9g8_19 = f9   * (REF10_crypto_int64) g8_19;
  REF10_crypto_int64 f9g9_38 = f9_2 * (REF10_crypto_int64) g9_19;
  REF10_crypto_int64 h0 = f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
  REF10_crypto_int64 h1 = f0g1+f1g0   +f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
  REF10_crypto_int64 h2 = f0g2+f1g1_2 +f2g0   +f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
  REF10_crypto_int64 h3 = f0g3+f1g2   +f2g1   +f3g0   +f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
  REF10_crypto_int64 h4 = f0g4+f1g3_2 +f2g2   +f3g1_2 +f4g0   +f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
  REF10_crypto_int64 h5 = f0g5+f1g4   +f2g3   +f3g2   +f4g1   +f5g0   +f6g9_19+f7g8_19+f8g7_19+f9g6_19;
  REF10_crypto_int64 h6 = f0g6+f1g5_2 +f2g4   +f3g3_2 +f4g2   +f5g1_2 +f6g0   +f7g9_38+f8g8_19+f9g7_38;
  REF10_crypto_int64 h7 = f0g7+f1g6   +f2g5   +f3g4   +f4g3   +f5g2   +f6g1   +f7g0   +f8g9_19+f9g8_19;
  REF10_crypto_int64 h8 = f0g8+f1g7_2 +f2g6   +f3g5_2 +f4g4   +f5g3_2 +f6g2   +f7g1_2 +f8g0   +f9g9_38;
  REF10_crypto_int64 h9 = f0g9+f1g8   +f2g7   +f3g6   +f4g5   +f5g4   +f6g3   +f7g2   +f8g1   +f9g0   ;
  REF10_crypto_int64 carry0;
  REF10_crypto_int64 carry1;
  REF10_crypto_int64 carry2;
  REF10_crypto_int64 carry3;
  REF10_crypto_int64 carry4;
  REF10_crypto_int64 carry5;
  REF10_crypto_int64 carry6;
  REF10_crypto_int64 carry7;
  REF10_crypto_int64 carry8;
  REF10_crypto_int64 carry9;

  /*
  |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
    i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
  |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
    i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
  */

  carry0 = (h0 + (REF10_crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (REF10_crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  /* |h0| <= 2^25 */
  /* |h4| <= 2^25 */
  /* |h1| <= 1.71*2^59 */
  /* |h5| <= 1.71*2^59 */

  carry1 = (h1 + (REF10_crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (REF10_crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  /* |h1| <= 2^24; from now on fits into int32 */
  /* |h5| <= 2^24; from now on fits into int32 */
  /* |h2| <= 1.41*2^60 */
  /* |h6| <= 1.41*2^60 */

  carry2 = (h2 + (REF10_crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (REF10_crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  /* |h2| <= 2^25; from now on fits into int32 unchanged */
  /* |h6| <= 2^25; from now on fits into int32 unchanged */
  /* |h3| <= 1.71*2^59 */
  /* |h7| <= 1.71*2^59 */

  carry3 = (h3 + (REF10_crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (REF10_crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
  /* |h3| <= 2^24; from now on fits into int32 unchanged */
  /* |h7| <= 2^24; from now on fits into int32 unchanged */
  /* |h4| <= 1.72*2^34 */
  /* |h8| <= 1.41*2^60 */

  carry4 = (h4 + (REF10_crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (REF10_crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
  /* |h4| <= 2^25; from now on fits into int32 unchanged */
  /* |h8| <= 2^25; from now on fits into int32 unchanged */
  /* |h5| <= 1.01*2^24 */
  /* |h9| <= 1.71*2^59 */

  carry9 = (h9 + (REF10_crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  /* |h9| <= 2^24; from now on fits into int32 unchanged */
  /* |h0| <= 1.1*2^39 */

  carry0 = (h0 + (REF10_crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  /* |h0| <= 2^25; from now on fits into int32 unchanged */
  /* |h1| <= 1.01*2^24 */

  h[0] = (int)h0;
  h[1] = (int)h1;
  h[2] = (int)h2;
  h[3] = (int)h3;
  h[4] = (int)h4;
  h[5] = (int)h5;
  h[6] = (int)h6;
  h[7] = (int)h7;
  h[8] = (int)h8;
  h[9] = (int)h9;
}
