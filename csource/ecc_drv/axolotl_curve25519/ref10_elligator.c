#include <string.h>
#include "ref10_fe.h"
#include "ref10_ge.h"
#include "ref10_crypto_uint32.h"
#include "ref10_crypto_hash_sha512.h"
#include "ref10_crypto_additions.h"

unsigned int REF10_legendre_is_nonsquare(REF10_fe in)
{
  REF10_fe temp;
  unsigned char bytes[32];
  REF10_fe_pow22523(temp, in);  /* temp = in^((q-5)/8) */
  REF10_fe_sq(temp, temp);      /*        in^((q-5)/4) */ 
  REF10_fe_sq(temp, temp);      /*        in^((q-5)/2) */
  REF10_fe_mul(temp, temp, in); /*        in^((q-3)/2) */
  REF10_fe_mul(temp, temp, in); /*        in^((q-1)/2) */

  /* temp is now the Legendre symbol:
   * 1  = square
   * 0  = input is zero
   * -1 = nonsquare
   */
  REF10_fe_tobytes(bytes, temp);
  return 1 & bytes[31];
}

void REF10_elligator(REF10_fe u, const REF10_fe r)
{
  /* r = input
   * x = -A/(1+2r^2)                # 2 is nonsquare
   * e = (x^3 + Ax^2 + x)^((q-1)/2) # legendre symbol
   * if e == 1 (square) or e == 0 (because x == 0 and 2r^2 + 1 == 0)
   *   u = x
   * if e == -1 (nonsquare)
   *   u = -x - A
   */
  REF10_fe A, one, twor2, twor2plus1, twor2plus1inv;
  REF10_fe x, e, Atemp, uneg;
  unsigned int nonsquare;

  REF10_fe_1(one);
  REF10_fe_0(A);
  A[0] = 486662;                         /* A = 486662 */

  REF10_fe_sq2(twor2, r);                      /* 2r^2 */
  REF10_fe_add(twor2plus1, twor2, one);        /* 1+2r^2 */
  REF10_fe_invert(twor2plus1inv, twor2plus1);  /* 1/(1+2r^2) */
  REF10_fe_mul(x, twor2plus1inv, A);           /* A/(1+2r^2) */
  REF10_fe_neg(x, x);                          /* x = -A/(1+2r^2) */

  REF10_fe_mont_rhs(e, x);                     /* e = x^3 + Ax^2 + x */
  nonsquare = REF10_legendre_is_nonsquare(e); 

  REF10_fe_0(Atemp);
  REF10_fe_cmov(Atemp, A, nonsquare);          /* 0, or A if nonsquare */
  REF10_fe_add(u, x, Atemp);                   /* x, or x+A if nonsquare */ 
  REF10_fe_neg(uneg, u);                       /* -x, or -x-A if nonsquare */
  REF10_fe_cmov(u, uneg, nonsquare);           /* x, or -x-A if nonsquare */
}

void REF10_hash_to_point(REF10_ge_p3* p, const unsigned char* in, const unsigned long in_len)
{
  unsigned char hash[64];
  REF10_fe h, u;
  unsigned char sign_bit;
  REF10_ge_p3 p3;

  REF10_crypto_hash_sha512(hash, in, in_len);

  /* take the high bit as Edwards sign bit */
  sign_bit = (hash[31] & 0x80) >> 7; 
  hash[31] &= 0x7F;
  REF10_fe_frombytes(h, hash); 
  REF10_elligator(u, h);

  REF10_ge_montx_to_p3(&p3, u, sign_bit);
  REF10_ge_scalarmult_cofactor(p, &p3);
}


