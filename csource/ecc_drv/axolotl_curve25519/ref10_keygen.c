#include "ref10_ge.h"
#include "ref10_keygen.h"
#include "ref10_crypto_additions.h"

void REF10_curve25519_keygen(unsigned char* curve25519_pubkey_out,
                       const unsigned char* curve25519_privkey_in)
{
  /* Perform a fixed-base multiplication of the Edwards base point,
     (which is efficient due to precalculated tables), then convert
     to the Curve25519 montgomery-format public key.

     NOTE: y=1 is converted to u=0 since REF10_fe_invert is mod-exp
  */

  REF10_ge_p3 ed; /* Ed25519 pubkey point */
  REF10_fe u;

  REF10_ge_scalarmult_base(&ed, curve25519_privkey_in);
  REF10_ge_p3_to_montx(u, &ed);
  REF10_fe_tobytes(curve25519_pubkey_out, u);
}
