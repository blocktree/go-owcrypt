#ifndef REF10_crypto_verify_32_H
#define REF10_crypto_verify_32_H

#define REF10_crypto_verify_32_ref_BYTES 32
#ifdef __cplusplus
#include <string>
extern "C" {
#endif
extern int REF10_crypto_verify_32_ref(const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define REF10_crypto_verify_32 REF10_crypto_verify_32_ref
#define REF10_crypto_verify_32_BYTES REF10_crypto_verify_32_ref_BYTES
#define REF10_crypto_verify_32_IMPLEMENTATION "crypto_verify/32/ref"
#ifndef REF10_crypto_verify_32_ref_VERSION
#define REF10_crypto_verify_32_ref_VERSION "-"
#endif
#define REF10_crypto_verify_32_VERSION REF10_crypto_verify_32_ref_VERSION

#endif
