#include "ref10_fe.h"
#include "ref10_crypto_int64.h"
#include "ref10_crypto_uint64.h"

static REF10_crypto_uint64 REF10_fe_fromebytes_load_3(const unsigned char *in)
{
  REF10_crypto_uint64 result;
  result = (REF10_crypto_uint64) in[0];
  result |= ((REF10_crypto_uint64) in[1]) << 8;
  result |= ((REF10_crypto_uint64) in[2]) << 16;
  return result;
}

static REF10_crypto_uint64 REF10_fe_fromebytes_load_4(const unsigned char *in)
{
  REF10_crypto_uint64 result;
  result = (REF10_crypto_uint64) in[0];
  result |= ((REF10_crypto_uint64) in[1]) << 8;
  result |= ((REF10_crypto_uint64) in[2]) << 16;
  result |= ((REF10_crypto_uint64) in[3]) << 24;
  return result;
}

/*
Ignores top bit of h.
*/

void REF10_fe_frombytes(REF10_fe h,const unsigned char *s)
{
  REF10_crypto_int64 h0 = REF10_fe_fromebytes_load_4(s);
  REF10_crypto_int64 h1 = REF10_fe_fromebytes_load_3(s + 4) << 6;
  REF10_crypto_int64 h2 = REF10_fe_fromebytes_load_3(s + 7) << 5;
  REF10_crypto_int64 h3 = REF10_fe_fromebytes_load_3(s + 10) << 3;
  REF10_crypto_int64 h4 = REF10_fe_fromebytes_load_3(s + 13) << 2;
  REF10_crypto_int64 h5 = REF10_fe_fromebytes_load_4(s + 16);
  REF10_crypto_int64 h6 = REF10_fe_fromebytes_load_3(s + 20) << 7;
  REF10_crypto_int64 h7 = REF10_fe_fromebytes_load_3(s + 23) << 5;
  REF10_crypto_int64 h8 = REF10_fe_fromebytes_load_3(s + 26) << 4;
  REF10_crypto_int64 h9 = (REF10_fe_fromebytes_load_3(s + 29) & 8388607) << 2;
  REF10_crypto_int64 carry0;
  REF10_crypto_int64 carry1;
  REF10_crypto_int64 carry2;
  REF10_crypto_int64 carry3;
  REF10_crypto_int64 carry4;
  REF10_crypto_int64 carry5;
  REF10_crypto_int64 carry6;
  REF10_crypto_int64 carry7;
  REF10_crypto_int64 carry8;
  REF10_crypto_int64 carry9;

  carry9 = (h9 + (REF10_crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  carry1 = (h1 + (REF10_crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry3 = (h3 + (REF10_crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry5 = (h5 + (REF10_crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  carry7 = (h7 + (REF10_crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

  carry0 = (h0 + (REF10_crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry2 = (h2 + (REF10_crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry4 = (h4 + (REF10_crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry6 = (h6 + (REF10_crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  carry8 = (h8 + (REF10_crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

  h[0] = (int)h0;
  h[1] = (int)h1;
  h[2] = (int)h2;
  h[3] = (int)h3;
  h[4] = (int)h4;
  h[5] = (int)h5;
  h[6] = (int)h6;
  h[7] = (int)h7;
  h[8] = (int)h8;
  h[9] = (int)h9;
}
