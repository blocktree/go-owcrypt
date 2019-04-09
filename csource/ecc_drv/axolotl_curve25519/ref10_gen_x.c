#include <string.h>
#include "ref10_crypto_additions.h"
#include "ref10_gen_x.h"
#include "ref10_gen_constants.h"
#include "ref10_gen_eddsa.h"
#include "ref10_gen_veddsa.h"
#include "ref10_gen_crypto_additions.h"
#include "ref10_zeroize.h"

static int REF10_convert_25519_pubkey(unsigned char* ed_pubkey_bytes, const unsigned char* x25519_pubkey_bytes) {
  REF10_fe u;
  REF10_fe y;

  /* Convert the X25519 public key into an Ed25519 public key.

     y = (u - 1) / (u + 1)

     NOTE: u=-1 is converted to y=0 since REF10_fe_invert is mod-exp
  */
  if (!REF10_fe_isreduced(x25519_pubkey_bytes))
      return -1;
  REF10_fe_frombytes(u, x25519_pubkey_bytes);
  REF10_fe_montx_to_edy(y, u);
  REF10_fe_tobytes(ed_pubkey_bytes, y);
  return 0;
}

int REF10_convert_X_to_Ed(unsigned char* ed, const unsigned char* x)
{
    return REF10_convert_25519_pubkey(ed, x);
}

int REF10_convert_Ed_to_X(unsigned char* x, const unsigned char* ed)
{
    REF10_fe u;
    REF10_fe y;
    REF10_fe_frombytes(y, ed);
    REF10_fe_montx_from_edy(u, y);
    REF10_fe_tobytes(x, u);
    if (!REF10_fe_isreduced(x))
        return -1;
    return 0;
}

static int REF10_calculate_25519_keypair(unsigned char* K_bytes, unsigned char* k_scalar, 
                            const unsigned char* x25519_privkey_scalar)
{
  unsigned char kneg[SCALARLEN];
  REF10_ge_p3 ed_pubkey_point;
  unsigned char sign_bit = 0;

  if (SCALARLEN != 32)
    return -1;

  /* Convert the Curve25519 privkey to an Ed25519 public key */
  REF10_ge_scalarmult_base(&ed_pubkey_point, x25519_privkey_scalar);
  REF10_ge_p3_tobytes(K_bytes, &ed_pubkey_point);

  /* Force Edwards sign bit to zero */
  sign_bit = (K_bytes[31] & 0x80) >> 7;
  memcpy(k_scalar, x25519_privkey_scalar, 32);
  REF10_sc_neg(kneg, k_scalar);
  REF10_sc_cmov(k_scalar, kneg, sign_bit); 
  K_bytes[31] &= 0x7F;

  REF10_zeroize(kneg, SCALARLEN);
  return 0;
}

int REF10_generalized_xeddsa_25519_sign(unsigned char* signature_out,
                              const unsigned char* x25519_privkey_scalar,
                              const unsigned char* msg, const unsigned long msg_len,
                              const unsigned char* random,
                              const unsigned char* customization_label,
                              const unsigned long customization_label_len)
{
  unsigned char K_bytes[POINTLEN];
  unsigned char k_scalar[SCALARLEN];
  int retval = -1;

  if (REF10_calculate_25519_keypair(K_bytes, k_scalar, x25519_privkey_scalar) != 0)
    return -1;

  retval = REF10_generalized_eddsa_25519_sign(signature_out, 
                                        K_bytes, k_scalar,
                                        msg, msg_len, random, 
                                        customization_label, customization_label_len);
  REF10_zeroize(k_scalar, SCALARLEN);
  return retval;
}

int REF10_generalized_xveddsa_25519_sign(
                  unsigned char* signature_out,
                  const unsigned char* x25519_privkey_scalar,
                  const unsigned char* msg, 
                  const unsigned long msg_len,
                  const unsigned char* random,
                  const unsigned char* customization_label,
                  const unsigned long customization_label_len)
{
  unsigned char K_bytes[POINTLEN];
  unsigned char k_scalar[SCALARLEN];
  int retval = -1;

  if (REF10_calculate_25519_keypair(K_bytes, k_scalar, x25519_privkey_scalar) != 0)
    return -1;

  retval = REF10_generalized_veddsa_25519_sign(signature_out, K_bytes, k_scalar, 
                                         msg, msg_len, random, 
                                         customization_label, customization_label_len);
  REF10_zeroize(k_scalar, SCALARLEN);
  return retval;
}

int REF10_generalized_xeddsa_25519_verify(
                  const unsigned char* signature,
                  const unsigned char* x25519_pubkey_bytes,
                  const unsigned char* msg, 
                  const unsigned long msg_len,
                  const unsigned char* customization_label,
                  const unsigned long customization_label_len)
{
  unsigned char K_bytes[POINTLEN];

  if (REF10_convert_25519_pubkey(K_bytes, x25519_pubkey_bytes) != 0)
      return -1;

  return REF10_generalized_eddsa_25519_verify(signature, K_bytes, msg, msg_len, 
                                        customization_label, customization_label_len);
}

int REF10_generalized_xveddsa_25519_verify(
                  unsigned char* vrf_out,
                  const unsigned char* signature,
                  const unsigned char* x25519_pubkey_bytes,
                  const unsigned char* msg, 
                  const unsigned long msg_len,
                  const unsigned char* customization_label,
                  const unsigned long customization_label_len)
{
  unsigned char K_bytes[POINTLEN];

  if (REF10_convert_25519_pubkey(K_bytes, x25519_pubkey_bytes) != 0)
      return -1;

  return REF10_generalized_veddsa_25519_verify(vrf_out, signature, K_bytes, msg, msg_len, 
                                         customization_label, customization_label_len);
}
