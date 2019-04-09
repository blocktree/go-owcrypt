#include <string.h>
#include "ref10_crypto_sign.h"
#include "ref10_crypto_hash_sha512.h"
#include "ref10_ge.h"
#include "ref10_sc.h"
#include "ref10_zeroize.h"
#include "ref10_crypto_additions.h"

/* NEW: Compare to pristine REF10_crypto_sign() 
   Uses explicit private key for nonce derivation and as scalar,
   instead of deriving both from a master key.
*/
int REF10_crypto_sign_modified(
  unsigned char *sm,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk, const unsigned char* pk,
  const unsigned char* random
)
{
  unsigned char nonce[64];
  unsigned char hram[64];
  REF10_ge_p3 R;
  int count=0;

  memmove(sm + 64,m,mlen);
  memmove(sm + 32,sk,32); /* NEW: Use privkey directly for nonce derivation */

  /* NEW : add prefix to separate hash uses - see .h */
  sm[0] = 0xFE;
  for (count = 1; count < 32; count++)
    sm[count] = 0xFF;

  /* NEW: add suffix of random data */
  memmove(sm + mlen + 64, random, 64);

  REF10_crypto_hash_sha512(nonce,sm,mlen + 128);
  memmove(sm + 32,pk,32);

  REF10_sc_reduce(nonce);
  
  REF10_ge_scalarmult_base(&R,nonce);
  REF10_ge_p3_tobytes(sm,&R);

  REF10_crypto_hash_sha512(hram,sm,mlen + 64);
  REF10_sc_reduce(hram);
  REF10_sc_muladd(sm + 32,hram,sk,nonce); /* NEW: Use privkey directly */

  /* Erase any traces of private scalar or
     nonce left in the stack from REF10_sc_muladd */
  REF10_zeroize_stack();
  REF10_zeroize(nonce, 64);
  return 0;
}
