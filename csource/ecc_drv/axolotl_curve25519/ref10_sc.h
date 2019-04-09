#ifndef SC_H
#define SC_H

/*
The set of scalars is \Z/l
where l = 2^252 + 27742317777372353535851937790883648493.
*/

#define REF10_sc_reduce REF10_crypto_sign_ed25519_ref10_sc_reduce
#define REF10_sc_muladd REF10_crypto_sign_ed25519_ref10_sc_muladd

extern void REF10_sc_reduce(unsigned char *);
extern void REF10_sc_muladd(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);

#endif
