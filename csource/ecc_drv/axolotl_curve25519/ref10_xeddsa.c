#include <string.h>
#include "ref10_ge.h"
#include "ref10_crypto_additions.h"
#include "ref10_zeroize.h"
#include "ref10_xeddsa.h"
#include "ref10_crypto_verify_32.h"

int REF10_xed25519_sign(unsigned char* signature_out,
                  const unsigned char* curve25519_privkey,
                  const unsigned char* msg, const unsigned long msg_len,
                  const unsigned char* random)
{
  unsigned char a[32], aneg[32];
  unsigned char A[32];
  REF10_ge_p3 ed_pubkey_point;
  unsigned char *sigbuf; /* working buffer */
  unsigned char sign_bit = 0;

  if ((sigbuf = malloc(msg_len + 128)) == 0) {
    memset(signature_out, 0, 64);
    return -1;
  }

  /* Convert the Curve25519 privkey to an Ed25519 public key */
  REF10_ge_scalarmult_base(&ed_pubkey_point, curve25519_privkey);
  REF10_ge_p3_tobytes(A, &ed_pubkey_point);

  /* Force Edwards sign bit to zero */
  sign_bit = (A[31] & 0x80) >> 7;
  memcpy(a, curve25519_privkey, 32);
  REF10_sc_neg(aneg, a);
  REF10_sc_cmov(a, aneg, sign_bit); 
  A[31] &= 0x7F;

  /* Perform an Ed25519 signature with explicit private key */
  REF10_crypto_sign_modified(sigbuf, msg, msg_len, a, A, random);
  memmove(signature_out, sigbuf, 64);

  REF10_zeroize(a, 32);
  REF10_zeroize(aneg, 32);
  free(sigbuf);
  return 0;
}

int REF10_xed25519_verify(const unsigned char* signature,
                    const unsigned char* curve25519_pubkey,
                    const unsigned char* msg, const unsigned long msg_len)
{
  REF10_fe u;
  REF10_fe y;
  unsigned char ed_pubkey[32];
  unsigned char verifybuf[REF10_MAX_MSG_LEN + 64]; /* working buffer */
  unsigned char verifybuf2[REF10_MAX_MSG_LEN + 64]; /* working buffer #2 */

  if (msg_len > REF10_MAX_MSG_LEN) {
    return -1;
  }

  /* Convert the Curve25519 public key into an Ed25519 public key.

     y = (u - 1) / (u + 1)

     NOTE: u=-1 is converted to y=0 since REF10_fe_invert is mod-exp
  */
  if (!REF10_fe_isreduced(curve25519_pubkey))
      return -1;
  REF10_fe_frombytes(u, curve25519_pubkey);
  REF10_fe_montx_to_edy(y, u);
  REF10_fe_tobytes(ed_pubkey, y);

  memmove(verifybuf, signature, 64);
  memmove(verifybuf+64, msg, msg_len);

  /* Then perform a normal Ed25519 verification, return 0 on success */
  /* The below call has a strange API: */
  /* verifybuf = R || S || message */
  /* verifybuf2 = internal to next call gets a copy of verifybuf, S gets 
     replaced with pubkey for hashing */
  return REF10_crypto_sign_open_modified(verifybuf2, verifybuf, 64 + msg_len, ed_pubkey);
}
