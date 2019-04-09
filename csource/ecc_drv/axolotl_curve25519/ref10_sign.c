#include <string.h>
#include "ref10_crypto_sign.h"
#include "ref10_crypto_hash_sha512.h"
#include "ref10_ge.h"
#include "ref10_sc.h"

int REF10_crypto_sign(
  unsigned char *sm,unsigned long long *smlen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk
)
{
  unsigned char pk[32];
  unsigned char az[64];
  unsigned char nonce[64];
  unsigned char hram[64];
  REF10_ge_p3 R;

  memmove(pk,sk + 32,32);

  REF10_crypto_hash_sha512(az,sk,32);
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  *smlen = mlen + 64;
  memmove(sm + 64,m,mlen);
  memmove(sm + 32,az + 32,32);
  REF10_crypto_hash_sha512(nonce,sm + 32,mlen + 32);
  memmove(sm + 32,pk,32);

  REF10_sc_reduce(nonce);
  REF10_ge_scalarmult_base(&R,nonce);
  REF10_ge_p3_tobytes(sm,&R);

  REF10_crypto_hash_sha512(hram,sm,mlen + 64);
  REF10_sc_reduce(hram);
  REF10_sc_muladd(sm + 32,hram,az,nonce);

  return 0;
}
