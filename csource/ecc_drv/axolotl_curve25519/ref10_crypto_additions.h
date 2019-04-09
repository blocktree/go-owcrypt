
#ifndef __CRYPTO_ADDITIONS__
#define __CRYPTO_ADDITIONS__

#include "ref10_crypto_uint32.h"
#include "ref10_fe.h"
#include "ref10_ge.h"

#define REF10_MAX_MSG_LEN 256

void REF10_sc_neg(unsigned char *b, const unsigned char *a);
void REF10_sc_cmov(unsigned char* f, const unsigned char* g, unsigned char b);

int REF10_fe_isequal(const REF10_fe f, const REF10_fe g);
int REF10_fe_isreduced(const unsigned char* s);
void REF10_fe_mont_rhs(REF10_fe v2, const REF10_fe u);
void REF10_fe_montx_to_edy(REF10_fe y, const REF10_fe u);
void REF10_fe_montx_from_edy(REF10_fe u, const REF10_fe y);
void REF10_fe_sqrt(REF10_fe b, const REF10_fe a);

int REF10_ge_isneutral(const REF10_ge_p3* q);
void REF10_ge_neg(REF10_ge_p3* r, const REF10_ge_p3 *p);
void REF10_ge_montx_to_p3(REF10_ge_p3* p, const REF10_fe u, const unsigned char ed_sign_bit);
void REF10_ge_p3_to_montx(REF10_fe u, const REF10_ge_p3 *p);
void REF10_ge_scalarmult(REF10_ge_p3 *h, const unsigned char *a, const REF10_ge_p3 *A);
void REF10_ge_scalarmult_cofactor(REF10_ge_p3 *q, const REF10_ge_p3 *p);

void REF10_elligator(REF10_fe u, const REF10_fe r);
void REF10_hash_to_point(REF10_ge_p3* p, const unsigned char* msg, const unsigned long in_len);

int REF10_crypto_sign_modified(
  unsigned char *sm,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk, /* Curve/Ed25519 private key */
  const unsigned char *pk, /* Ed25519 public key */
  const unsigned char *random /* 64 bytes random to hash into nonce */
  );

int REF10_crypto_sign_open_modified(
  unsigned char *m,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk
  );


#endif
