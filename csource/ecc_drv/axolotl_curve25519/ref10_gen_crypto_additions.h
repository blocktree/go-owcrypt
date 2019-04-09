
#ifndef __GEN_CRYPTO_ADDITIONS__
#define __GEN_CRYPTO_ADDITIONS__

#include "ref10_crypto_uint32.h"
#include "ref10_fe.h"
#include "ref10_ge.h"

int REF10_sc_isreduced(const unsigned char* s);

int REF10_point_isreduced(const unsigned char* p);

void REF10_ge_p3_add(REF10_ge_p3 *r, const REF10_ge_p3 *p, const REF10_ge_p3 *q);

#endif

