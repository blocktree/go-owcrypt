#ifndef FE_H
#define FE_H

#include "ref10_crypto_int32.h"

typedef REF10_crypto_int32 REF10_fe[10];

/*
fe means field element.
Here the field is \Z/(2^255-19).
An element t, entries t[0]...t[9], represents the integer
t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
Bounds on each t[i] vary depending on context.
*/

#define REF10_fe_frombytes REF10_crypto_sign_ed25519_ref10_fe_frombytes
#define REF10_fe_tobytes REF10_crypto_sign_ed25519_ref10_fe_tobytes
#define REF10_fe_copy REF10_crypto_sign_ed25519_ref10_fe_copy
#define REF10_fe_isnonzero REF10_crypto_sign_ed25519_ref10_fe_isnonzero
#define REF10_fe_isnegative REF10_crypto_sign_ed25519_ref10_fe_isnegative
#define REF10_fe_0 REF10_crypto_sign_ed25519_ref10_fe_0
#define REF10_fe_1 REF10_crypto_sign_ed25519_ref10_fe_1
#define REF10_fe_cswap REF10_crypto_sign_ed25519_ref10_fe_cswap
#define REF10_fe_cmov REF10_crypto_sign_ed25519_ref10_fe_cmov
#define REF10_fe_add REF10_crypto_sign_ed25519_ref10_fe_add
#define REF10_fe_sub REF10_crypto_sign_ed25519_ref10_fe_sub
#define REF10_fe_neg REF10_crypto_sign_ed25519_ref10_fe_neg
#define REF10_fe_mul REF10_crypto_sign_ed25519_ref10_REF10_fe_mul
#define REF10_fe_sq REF10_crypto_sign_ed25519_ref10_fe_sq
#define REF10_fe_sq2 REF10_crypto_sign_ed25519_ref10_fe_sq2
#define REF10_fe_mul121666 REF10_crypto_sign_ed25519_ref10_REF10_fe_mul121666
#define REF10_fe_invert REF10_crypto_sign_ed25519_ref10_fe_invert
#define REF10_fe_pow22523 REF10_crypto_sign_ed25519_ref10_fe_pow22523

extern void REF10_fe_frombytes(REF10_fe,const unsigned char *);
extern void REF10_fe_tobytes(unsigned char *,const REF10_fe);

extern void REF10_fe_copy(REF10_fe,const REF10_fe);
extern int REF10_fe_isnonzero(const REF10_fe);
extern int REF10_fe_isnegative(const REF10_fe);
extern void REF10_fe_0(REF10_fe);
extern void REF10_fe_1(REF10_fe);
extern void REF10_fe_cswap(REF10_fe,REF10_fe,unsigned int);
extern void REF10_fe_cmov(REF10_fe,const REF10_fe,unsigned int);

extern void REF10_fe_add(REF10_fe,const REF10_fe,const REF10_fe);
extern void REF10_fe_sub(REF10_fe,const REF10_fe,const REF10_fe);
extern void REF10_fe_neg(REF10_fe,const REF10_fe);
extern void REF10_fe_mul(REF10_fe,const REF10_fe,const REF10_fe);
extern void REF10_fe_sq(REF10_fe,const REF10_fe);
extern void REF10_fe_sq2(REF10_fe,const REF10_fe);
extern void REF10_fe_mul121666(REF10_fe,const REF10_fe);
extern void REF10_fe_invert(REF10_fe,const REF10_fe);
extern void REF10_fe_pow22523(REF10_fe,const REF10_fe);

#endif
