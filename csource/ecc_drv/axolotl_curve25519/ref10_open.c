#include <string.h>
#include "ref10_crypto_sign.h"
#include "ref10_crypto_hash_sha512.h"
#include "ref10_crypto_verify_32.h"
#include "ref10_ge.h"
#include "ref10_sc.h"

int REF10_crypto_sign_open(
  unsigned char *m,unsigned long long *mlen,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk
)
{
  unsigned char pkcopy[32];
  unsigned char rcopy[32];
  unsigned char scopy[32];
  unsigned char h[64];
  unsigned char rcheck[32];
  REF10_ge_p3 A;
  REF10_ge_p2 R;

  if (smlen < 64) goto badsig;
  if (sm[63] & 224) goto badsig;
  if (REF10_ge_frombytes_negate_vartime(&A,pk) != 0) goto badsig;

  memmove(pkcopy,pk,32);
  memmove(rcopy,sm,32);
  memmove(scopy,sm + 32,32);

  memmove(m,sm,smlen);
  memmove(m + 32,pkcopy,32);
  REF10_crypto_hash_sha512(h,m,smlen);
  REF10_sc_reduce(h);

  REF10_ge_double_scalarmult_vartime(&R,h,&A,scopy);
  REF10_ge_tobytes(rcheck,&R);
  if (REF10_crypto_verify_32(rcheck,rcopy) == 0) {
    memmove(m,m + 64,smlen - 64);
    memset(m + smlen - 64,0,64);
    *mlen = smlen - 64;
    return 0;
  }

badsig:
  *mlen = -1;
  memset(m,0,smlen);
  return -1;
}
