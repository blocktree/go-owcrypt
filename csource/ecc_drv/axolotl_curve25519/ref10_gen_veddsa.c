#include <string.h>
#include "ref10_gen_eddsa.h"
#include "ref10_gen_veddsa.h"
#include "ref10_gen_constants.h"
#include "ref10_gen_labelset.h"
#include "ref10_gen_crypto_additions.h"
#include "ref10_crypto_hash_sha512.h"
#include "ref10_crypto_verify_32.h"
#include "ref10_crypto_additions.h"
#include "ref10_zeroize.h"
#include "ref10_ge.h"
#include "ref10_sc.h"
//#include "ref10_utility.h"

static int REF10_generalized_calculate_Bv(REF10_ge_p3* Bv_point,
                              const unsigned char* labelset, const unsigned long labelset_len,
                              const unsigned char* K_bytes,
                              unsigned char* M_buf, const unsigned long M_start, const unsigned long M_len)
{
  unsigned char* bufptr;
  unsigned long prefix_len = 0;

  if (REF10_labelset_validate(labelset, labelset_len) != 0)
    return -1;
  if (Bv_point == NULL || K_bytes == NULL || M_buf == NULL)
    return -1;

  prefix_len = 2*POINTLEN + labelset_len;
  if (prefix_len > M_start)
    return -1;

  bufptr = M_buf + M_start - prefix_len;
  bufptr = REF10_buffer_add(bufptr, M_buf + M_start, B_bytes, POINTLEN);
  bufptr = REF10_buffer_add(bufptr, M_buf + M_start, labelset, labelset_len);
  bufptr = REF10_buffer_add(bufptr, M_buf + M_start, K_bytes, POINTLEN);
  if (bufptr == NULL || bufptr != M_buf + M_start)
    return -1;

  REF10_hash_to_point(Bv_point, M_buf + M_start - prefix_len, prefix_len + M_len);
  if (REF10_ge_isneutral(Bv_point))
    return -1;
  return 0;
}

static int REF10_generalized_calculate_vrf_output(unsigned char* vrf_output,
                                     const unsigned char* labelset, const unsigned long labelset_len,
                                     const REF10_ge_p3* cKv_point)
{
  unsigned char buf[BUFLEN];
  unsigned char* bufptr = buf;
  unsigned char* bufend = buf + BUFLEN;
  unsigned char cKv_bytes[POINTLEN];
  unsigned char hash[HASHLEN];

  if (vrf_output == NULL)
    return -1;
  memset(vrf_output, 0, VRFOUTPUTLEN);

  if (labelset_len + 2*POINTLEN > BUFLEN)
    return -1;
  if (REF10_labelset_validate(labelset, labelset_len) != 0)
    return -1;
  if (cKv_point == NULL)
    return -1;
  if (VRFOUTPUTLEN > HASHLEN)
    return -1;

  REF10_ge_p3_tobytes(cKv_bytes, cKv_point);

  bufptr = REF10_buffer_add(bufptr, bufend, B_bytes, POINTLEN);
  bufptr = REF10_buffer_add(bufptr, bufend, labelset, labelset_len);
  bufptr = REF10_buffer_add(bufptr, bufend, cKv_bytes, POINTLEN);
  if (bufptr == NULL)
    return -1;
  if (bufptr - buf > BUFLEN)
    return -1;
  REF10_crypto_hash_sha512(hash, buf, bufptr - buf);
  memcpy(vrf_output, hash, VRFOUTPUTLEN);
  return 0;
}

int REF10_generalized_veddsa_25519_sign(
                  unsigned char* signature_out,
                  const unsigned char* eddsa_25519_pubkey_bytes,
                  const unsigned char* eddsa_25519_privkey_scalar,
                  const unsigned char* msg, 
                  const unsigned long msg_len,
                  const unsigned char* random,
                  const unsigned char* customization_label,
                  const unsigned long customization_label_len)
{
  unsigned char labelset[LABELSETMAXLEN];
  unsigned long labelset_len = 0;
  REF10_ge_p3 Bv_point;
  REF10_ge_p3 Kv_point;
  REF10_ge_p3 Rv_point;
  unsigned char Bv_bytes[POINTLEN];
  unsigned char Kv_bytes[POINTLEN];
  unsigned char Rv_bytes[POINTLEN];
  unsigned char R_bytes[POINTLEN];
  unsigned char r_scalar[SCALARLEN];
  unsigned char h_scalar[SCALARLEN];
  unsigned char s_scalar[SCALARLEN];
  unsigned char extra[3*POINTLEN];
  unsigned char* M_buf = NULL;
  char* protocol_name = "VEdDSA_25519_SHA512_Elligator2";

  if (signature_out == NULL)
    goto err;
  memset(signature_out, 0, VRFSIGNATURELEN);

  if (eddsa_25519_pubkey_bytes == NULL)
    goto err;
  if (eddsa_25519_privkey_scalar == NULL)
    goto err;
  if (msg == NULL)
    goto err;
  if (customization_label == NULL && customization_label_len != 0)
    goto err;
  if (customization_label_len > LABELMAXLEN)
    goto err;
  if (msg_len > MSGMAXLEN)
    goto err;

  if ((M_buf = malloc(msg_len + MSTART)) == 0) {
    goto err;
  }
  memcpy(M_buf + MSTART, msg, msg_len);

  //  labelset = new_labelset(protocol_name, customization_label)
  if (REF10_labelset_new(labelset, &labelset_len, LABELSETMAXLEN, 
                   (unsigned char*)protocol_name, strlen(protocol_name), 
                   customization_label, customization_label_len) != 0)
    goto err;

  //  labelset1 = add_label(labels, "1")
  //  Bv = hash(hash(labelset1 || K) || M)
  //  Kv = k * Bv
  REF10_labelset_add(labelset, &labelset_len, LABELSETMAXLEN, (unsigned char*)"1", 1);
  if (REF10_generalized_calculate_Bv(&Bv_point, labelset, labelset_len, 
                               eddsa_25519_pubkey_bytes, M_buf, MSTART, msg_len) != 0)
    goto err;
  REF10_ge_scalarmult(&Kv_point, eddsa_25519_privkey_scalar, &Bv_point);
  REF10_ge_p3_tobytes(Bv_bytes, &Bv_point);
  REF10_ge_p3_tobytes(Kv_bytes, &Kv_point);

  //  labelset2 = add_label(labels, "2")
  //  R, r = commit(labelset2, (Bv || Kv), (K,k), Z, M) 
  labelset[labelset_len-1] = (unsigned char)'2';
  memcpy(extra, Bv_bytes, POINTLEN);
  memcpy(extra + POINTLEN, Kv_bytes, POINTLEN);
  if (generalized_commit(R_bytes, r_scalar, 
                         labelset, labelset_len, 
                         extra, 2*POINTLEN, 
                         eddsa_25519_pubkey_bytes, eddsa_25519_privkey_scalar, 
                         random, M_buf, MSTART, msg_len) != 0)
    goto err;

  //  Rv = r * Bv
  REF10_ge_scalarmult(&Rv_point, r_scalar, &Bv_point);
  REF10_ge_p3_tobytes(Rv_bytes, &Rv_point);

  //  labelset3 = add_label(labels, "3")
  //  h = challenge(labelset3, (Bv || Kv || Rv), R, K, M)  
  labelset[labelset_len-1] = (unsigned char)'3';
  memcpy(extra + 2*POINTLEN, Rv_bytes, POINTLEN);
  if (REF10_generalized_challenge(h_scalar, 
                            labelset, labelset_len, 
                            extra, 3*POINTLEN, 
                            R_bytes, eddsa_25519_pubkey_bytes, 
                            M_buf, MSTART, msg_len) != 0)
    goto err;

  //  s = prove(r, k, h)
  if (REF10_generalized_prove(s_scalar, r_scalar, eddsa_25519_privkey_scalar, h_scalar) != 0)
    goto err;

  //  return (Kv || h || s)
  memcpy(signature_out, Kv_bytes, POINTLEN);
  memcpy(signature_out + POINTLEN, h_scalar, SCALARLEN);
  memcpy(signature_out + POINTLEN + SCALARLEN, s_scalar, SCALARLEN);

  REF10_zeroize(r_scalar, SCALARLEN);
  REF10_zeroize_stack();
  free(M_buf);
  return 0;

err:
  REF10_zeroize(r_scalar, SCALARLEN);
  REF10_zeroize_stack();
  free(M_buf);
  return -1;
}

int REF10_generalized_veddsa_25519_verify(
                  unsigned char* vrf_out,
                  const unsigned char* signature,
                  const unsigned char* eddsa_25519_pubkey_bytes,
                  const unsigned char* msg, 
                  const unsigned long msg_len,
                  const unsigned char* customization_label,
                  const unsigned long customization_label_len)
{
  unsigned char labelset[LABELSETMAXLEN];
  unsigned long labelset_len = 0;
  const unsigned char* Kv_bytes;
  const unsigned char* h_scalar;
  const unsigned char* s_scalar;
  REF10_ge_p3 Bv_point, K_point, Kv_point, cK_point, cKv_point;
  unsigned char Bv_bytes[POINTLEN];
  unsigned char R_calc_bytes[POINTLEN];
  unsigned char Rv_calc_bytes[POINTLEN];
  unsigned char h_calc_scalar[SCALARLEN];
  unsigned char extra[3*POINTLEN];
  unsigned char* M_buf = NULL;
  char* protocol_name = "VEdDSA_25519_SHA512_Elligator2";

  if (vrf_out == NULL)
    goto err;
  memset(vrf_out, 0, VRFOUTPUTLEN);

  if (signature == NULL)
    goto err;
  if (eddsa_25519_pubkey_bytes == NULL)
    goto err;
  if (msg == NULL)
    goto err;
  if (customization_label == NULL && customization_label_len != 0)
    goto err;
  if (customization_label_len > LABELMAXLEN)
    goto err;
  if (msg_len > MSGMAXLEN)
    goto err;

  if ((M_buf = malloc(msg_len + MSTART)) == 0) {
    goto err;
  }
  memcpy(M_buf + MSTART, msg, msg_len);

  Kv_bytes = signature;
  h_scalar = signature + POINTLEN;
  s_scalar = signature + POINTLEN + SCALARLEN;

  if (!REF10_point_isreduced(eddsa_25519_pubkey_bytes))
    goto err;
  if (!REF10_point_isreduced(Kv_bytes))
    goto err;
  if (!REF10_sc_isreduced(h_scalar))
    goto err;
  if (!REF10_sc_isreduced(s_scalar))
    goto err;

  //  labelset = new_labelset(protocol_name, customization_label)
  if (REF10_labelset_new(labelset, &labelset_len, LABELSETMAXLEN, 
                   (unsigned char*)protocol_name, strlen(protocol_name), 
                   customization_label, customization_label_len) != 0)
    goto err;

  //  labelset1 = add_label(labels, "1")
  //  Bv = hash(hash(labelset1 || K) || M)
  REF10_labelset_add(labelset, &labelset_len, LABELSETMAXLEN, (unsigned char*)"1", 1);
  if (REF10_generalized_calculate_Bv(&Bv_point, labelset, labelset_len, 
                               eddsa_25519_pubkey_bytes, M_buf, MSTART, msg_len) != 0)
    goto err;
  REF10_ge_p3_tobytes(Bv_bytes, &Bv_point);

  //  R = solve_commitment(B, s, K, h)
  if (REF10_generalized_solve_commitment(R_calc_bytes, &K_point, NULL, 
                                   s_scalar, eddsa_25519_pubkey_bytes, h_scalar) != 0)
    goto err;

  //  Rv = solve_commitment(Bv, s, Kv, h)
  if (REF10_generalized_solve_commitment(Rv_calc_bytes, &Kv_point, &Bv_point, 
                                   s_scalar, Kv_bytes, h_scalar) != 0)
    goto err;

  REF10_ge_scalarmult_cofactor(&cK_point, &K_point);
  REF10_ge_scalarmult_cofactor(&cKv_point, &Kv_point);
  if (REF10_ge_isneutral(&cK_point) || REF10_ge_isneutral(&cKv_point) || REF10_ge_isneutral(&Bv_point))
    goto err;

  //  labelset3 = add_label(labels, "3")
  //  h = challenge(labelset3, (Bv || Kv || Rv), R, K, M)  
  labelset[labelset_len-1] = (unsigned char)'3';
  memcpy(extra, Bv_bytes, POINTLEN);
  memcpy(extra + POINTLEN, Kv_bytes, POINTLEN);
  memcpy(extra + 2*POINTLEN, Rv_calc_bytes, POINTLEN);
  if (REF10_generalized_challenge(h_calc_scalar, 
                            labelset, labelset_len, 
                            extra, 3*POINTLEN, 
                            R_calc_bytes, eddsa_25519_pubkey_bytes, 
                            M_buf, MSTART, msg_len) != 0)
    goto err;

  // if bytes_equal(h, h')
  if (REF10_crypto_verify_32(h_scalar, h_calc_scalar) != 0)
    goto err;

  //  labelset4 = add_label(labels, "4")
  //  v = hash(labelset4 || c*Kv)
  labelset[labelset_len-1] = (unsigned char)'4';
  if (REF10_generalized_calculate_vrf_output(vrf_out, labelset, labelset_len, &cKv_point) != 0)
    goto err;

  free(M_buf);
  return 0;

err:
  free(M_buf);
  return -1;
}

