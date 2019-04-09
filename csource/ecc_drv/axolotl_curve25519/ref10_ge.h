#ifndef GE_H
#define GE_H

/*
ge means group element.

Here the group is the set of pairs (x,y) of field elements (see fe.h)
satisfying -x^2 + y^2 = 1 + d x^2y^2
where d = -121665/121666.

Representations:
  REF10_ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
  REF10_ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
  REF10_ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
  REF10_ge_precomp (Duif): (y+x,y-x,2dxy)
*/

#include "ref10_fe.h"

typedef struct {
  REF10_fe X;
  REF10_fe Y;
  REF10_fe Z;
} REF10_ge_p2;

typedef struct {
  REF10_fe X;
  REF10_fe Y;
  REF10_fe Z;
  REF10_fe T;
} REF10_ge_p3;

typedef struct {
  REF10_fe X;
  REF10_fe Y;
  REF10_fe Z;
  REF10_fe T;
} REF10_ge_p1p1;

typedef struct {
  REF10_fe yplusx;
  REF10_fe yminusx;
  REF10_fe xy2d;
} REF10_ge_precomp;

typedef struct {
  REF10_fe YplusX;
  REF10_fe YminusX;
  REF10_fe Z;
  REF10_fe T2d;
} REF10_ge_cached;

#define REF10_ge_frombytes_negate_vartime REF10_crypto_sign_ed25519_ref10_ge_frombytes_negate_vartime
#define REF10_ge_tobytes REF10_crypto_sign_ed25519_ref10_ge_tobytes
#define REF10_ge_p3_tobytes REF10_crypto_sign_ed25519_ref10_ge_p3_tobytes

#define REF10_ge_p2_0 REF10_crypto_sign_ed25519_ref10_ge_p2_0
#define REF10_ge_p3_0 REF10_crypto_sign_ed25519_ref10_ge_p3_0
#define REF10_ge_precomp_0 REF10_crypto_sign_ed25519_ref10_ge_precomp_0
#define REF10_ge_p3_to_p2 REF10_crypto_sign_ed25519_ref10_ge_p3_to_p2
#define REF10_ge_p3_to_cached REF10_crypto_sign_ed25519_ref10_ge_p3_to_cached
#define REF10_ge_p1p1_to_p2 REF10_crypto_sign_ed25519_ref10_ge_p1p1_to_p2
#define REF10_ge_p1p1_to_p3 REF10_crypto_sign_ed25519_ref10_ge_p1p1_to_p3
#define REF10_ge_p2_dbl REF10_crypto_sign_ed25519_ref10_ge_p2_dbl
#define REF10_ge_p3_dbl REF10_crypto_sign_ed25519_ref10_ge_p3_dbl

#define REF10_ge_madd REF10_crypto_sign_ed25519_ref10_ge_madd
#define REF10_ge_msub REF10_crypto_sign_ed25519_ref10_ge_msub
#define REF10_ge_add REF10_crypto_sign_ed25519_ref10_ge_add
#define REF10_ge_sub REF10_crypto_sign_ed25519_ref10_ge_sub
#define REF10_ge_scalarmult_base REF10_crypto_sign_ed25519_ref10_REF10_ge_scalarmult_base
#define REF10_ge_double_scalarmult_vartime REF10_crypto_sign_ed25519_ref10_ge_double_scalarmult_vartime

extern void REF10_ge_tobytes(unsigned char *,const REF10_ge_p2 *);
extern void REF10_ge_p3_tobytes(unsigned char *,const REF10_ge_p3 *);
extern int REF10_ge_frombytes_negate_vartime(REF10_ge_p3 *,const unsigned char *);

extern void REF10_ge_p2_0(REF10_ge_p2 *);
extern void REF10_ge_p3_0(REF10_ge_p3 *);
extern void REF10_ge_precomp_0(REF10_ge_precomp *);
extern void REF10_ge_p3_to_p2(REF10_ge_p2 *,const REF10_ge_p3 *);
extern void REF10_ge_p3_to_cached(REF10_ge_cached *,const REF10_ge_p3 *);
extern void REF10_ge_p1p1_to_p2(REF10_ge_p2 *,const REF10_ge_p1p1 *);
extern void REF10_ge_p1p1_to_p3(REF10_ge_p3 *,const REF10_ge_p1p1 *);
extern void REF10_ge_p2_dbl(REF10_ge_p1p1 *,const REF10_ge_p2 *);
extern void REF10_ge_p3_dbl(REF10_ge_p1p1 *,const REF10_ge_p3 *);

extern void REF10_ge_madd(REF10_ge_p1p1 *,const REF10_ge_p3 *,const REF10_ge_precomp *);
extern void REF10_ge_msub(REF10_ge_p1p1 *,const REF10_ge_p3 *,const REF10_ge_precomp *);
extern void REF10_ge_add(REF10_ge_p1p1 *,const REF10_ge_p3 *,const REF10_ge_cached *);
extern void REF10_ge_sub(REF10_ge_p1p1 *,const REF10_ge_p3 *,const REF10_ge_cached *);
extern void REF10_ge_scalarmult_base(REF10_ge_p3 *,const unsigned char *);
extern void REF10_ge_double_scalarmult_vartime(REF10_ge_p2 *,const unsigned char *,const REF10_ge_p3 *,const unsigned char *);

#endif
