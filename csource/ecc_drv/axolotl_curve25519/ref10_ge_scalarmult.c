#include "ref10_crypto_uint32.h"
#include "ref10_ge.h"
#include "ref10_crypto_additions.h"

static unsigned char REF10_ge_scalarmult_base_equal(signed char b,signed char c)
{
  unsigned char ub = b;
  unsigned char uc = c;
  unsigned char x = ub ^ uc; /* 0: yes; 1..255: no */
  REF10_crypto_uint32 y = x; /* 0: yes; 1..255: no */
  y -= 1; /* 4294967295: yes; 0..254: no */
  y >>= 31; /* 1: yes; 0: no */
  return y;
}

static unsigned char REF10_ge_scalarnult_negative(signed char b)
{
  unsigned long long x = b; /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
  x >>= 63; /* 1: yes; 0: no */
  return x;
}

static void REF10_ge_scalarnult_cmov(REF10_ge_cached *t,const REF10_ge_cached *u,unsigned char b)
{
  REF10_fe_cmov(t->YplusX,u->YplusX,b);
  REF10_fe_cmov(t->YminusX,u->YminusX,b);
  REF10_fe_cmov(t->Z,u->Z,b);
  REF10_fe_cmov(t->T2d,u->T2d,b);
}

static void REF10_ge_scalarnult_select(REF10_ge_cached *t,const REF10_ge_cached *pre, signed char b)
{
  REF10_ge_cached minust;
  unsigned char bnegative = REF10_ge_scalarnult_negative(b);
  unsigned char babs = b - (((-bnegative) & b) << 1);

  REF10_fe_1(t->YplusX);
  REF10_fe_1(t->YminusX);
  REF10_fe_1(t->Z);
  REF10_fe_0(t->T2d);

  REF10_ge_scalarnult_cmov(t,pre+0,REF10_ge_scalarmult_base_equal(babs,1));
  REF10_ge_scalarnult_cmov(t,pre+1,REF10_ge_scalarmult_base_equal(babs,2));
  REF10_ge_scalarnult_cmov(t,pre+2,REF10_ge_scalarmult_base_equal(babs,3));
  REF10_ge_scalarnult_cmov(t,pre+3,REF10_ge_scalarmult_base_equal(babs,4));
  REF10_ge_scalarnult_cmov(t,pre+4,REF10_ge_scalarmult_base_equal(babs,5));
  REF10_ge_scalarnult_cmov(t,pre+5,REF10_ge_scalarmult_base_equal(babs,6));
  REF10_ge_scalarnult_cmov(t,pre+6,REF10_ge_scalarmult_base_equal(babs,7));
  REF10_ge_scalarnult_cmov(t,pre+7,REF10_ge_scalarmult_base_equal(babs,8));
  REF10_fe_copy(minust.YplusX,t->YminusX);
  REF10_fe_copy(minust.YminusX,t->YplusX);
  REF10_fe_copy(minust.Z,t->Z);
  REF10_fe_neg(minust.T2d,t->T2d);
  REF10_ge_scalarnult_cmov(t,&minust,bnegative);
}

/*
h = a * B
where a = a[0]+256*a[1]+...+256^31 a[31]
B is the Ed25519 base point (x,4/5) with x positive.

Preconditions:
  a[31] <= 127
*/

void REF10_ge_scalarmult(REF10_ge_p3 *h, const unsigned char *a, const REF10_ge_p3 *A)
{
  signed char e[64];
  signed char carry;
  REF10_ge_p1p1 r;
  REF10_ge_p2 s;
  REF10_ge_p3 t0, t1, t2;
  REF10_ge_cached t, pre[8];
  int i;

  for (i = 0;i < 32;++i) {
    e[2 * i + 0] = (a[i] >> 0) & 15;
    e[2 * i + 1] = (a[i] >> 4) & 15;
  }
  /* each e[i] is between 0 and 15 */
  /* e[63] is between 0 and 7 */

  carry = 0;
  for (i = 0;i < 63;++i) {
    e[i] += carry;
    carry = e[i] + 8;
    carry >>= 4;
    e[i] -= carry << 4;
  }
  e[63] += carry;
  /* each e[i] is between -8 and 8 */

  // Precomputation:
  REF10_ge_p3_to_cached(pre+0, A); // A

  REF10_ge_p3_dbl(&r, A);
  REF10_ge_p1p1_to_p3(&t0, &r);
  REF10_ge_p3_to_cached(pre+1, &t0); // 2A

  REF10_ge_add(&r, A, pre+1);
  REF10_ge_p1p1_to_p3(&t1, &r);
  REF10_ge_p3_to_cached(pre+2, &t1); // 3A

  REF10_ge_p3_dbl(&r, &t0);
  REF10_ge_p1p1_to_p3(&t0, &r);
  REF10_ge_p3_to_cached(pre+3, &t0); // 4A

  REF10_ge_add(&r, A, pre+3);
  REF10_ge_p1p1_to_p3(&t2, &r);
  REF10_ge_p3_to_cached(pre+4, &t2); // 5A

  REF10_ge_p3_dbl(&r, &t1);
  REF10_ge_p1p1_to_p3(&t1, &r);
  REF10_ge_p3_to_cached(pre+5, &t1); // 6A

  REF10_ge_add(&r, A, pre+5);
  REF10_ge_p1p1_to_p3(&t1, &r);
  REF10_ge_p3_to_cached(pre+6, &t1); // 7A

  REF10_ge_p3_dbl(&r, &t0);
  REF10_ge_p1p1_to_p3(&t0, &r);
  REF10_ge_p3_to_cached(pre+7, &t0); // 8A

  REF10_ge_p3_0(h);

  for (i = 63;i > 0; i--) {
    REF10_ge_scalarnult_select(&t,pre,e[i]);
    REF10_ge_add(&r, h, &t);
    REF10_ge_p1p1_to_p2(&s,&r);

    REF10_ge_p2_dbl(&r,&s); REF10_ge_p1p1_to_p2(&s,&r);
    REF10_ge_p2_dbl(&r,&s); REF10_ge_p1p1_to_p2(&s,&r);
    REF10_ge_p2_dbl(&r,&s); REF10_ge_p1p1_to_p2(&s,&r);
    REF10_ge_p2_dbl(&r,&s); REF10_ge_p1p1_to_p3(h,&r);

  }
  REF10_ge_scalarnult_select(&t,pre,e[0]);
  REF10_ge_add(&r, h, &t);
  REF10_ge_p1p1_to_p3(h,&r);
}
