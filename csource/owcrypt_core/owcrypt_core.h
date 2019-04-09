#include <stdio.h>
#include "type.h"

#ifndef OWCRYPT_CORE_H
#define OWCRYPT_CORE_H


#define OWCRYPT 32

//#define owc_unit int
typedef int owc_unit;
//#define owc_double_unit long long
typedef long long owc_double_unit;
//typedef unsigned owc_unit owc_small;
typedef unsigned int owc_small;
//typedef unsigned owc_double_unit owc_large;
typedef unsigned long long owc_large;

#define OWC_INT_BITS 32


#define BASE_LIMMIT ((owc_small)1<<(OWCRYPT-1))
#define owc_abs(x)  ((x)<0? (-(x)) : (x))

#define OFF 0
#define ON 1
#define PLUS 1
#define MINUS (-1)




 #define OWC_TOBYTE(x) ((unsigned char)(x))



struct bignum
{
    unsigned int len;
    owc_small *w;
};                

typedef struct bignum *OWC_BN;

#define OWC_MSB ((unsigned int)1<<(OWC_INT_BITS-1))

#define OWC_OB (OWC_MSB-1)


#define OWC_TOOBIG (1<<(OWC_INT_BITS-2))

#define OWC_BOTTOM 0
#define OWC_TOP 1


union doubleword
{
    owc_large d;
    owc_small h[2];
};


#define OWC_POINT_GENERAL    0
#define OWC_POINT_NORMALIZED 1
#define OWC_POINT_INFINITY   2

#define OWC_PASS       0
#define OWC_ADD        1
#define OWC_DOUBLE     2


#define OWC_CURVE_LEN_WORD  8 //32 / 4

typedef struct {
int marker;
OWC_BN X;
OWC_BN Y;
} owc_point;




typedef struct {
    char *tmp_alloc;
    OWC_BN tmp0,tmp1,tmp2,tmp3,tmp4,tmp5,tmp6,tmp7,tmp8,tmp9,tmp10,tmp11,tmp12,tmp13,tmp14,tmp15;
    OWC_BN one;
    OWC_BN A,B;
    int    Asize,Bsize;
    owc_small base;
    owc_small apbase;
    int   pack;
    int   lg2b;
    owc_small base2;
    int   nib;
    BOOL  check;
    BOOL  active;
    owc_small ndash;
    OWC_BN modulus;
    OWC_BN pR;
    BOOL ACTIVE;
    BOOL MONTY;
    int qnr;
    int cnr;
    int pmod8;
    int pmod9;
    BOOL NO_CARRY;
} owcrypt;


extern owc_small owc_shiftbits(owc_small,int);
extern owc_small owc_setbase(owcrypt *pr_owc, owc_small);

extern void  owc_lzero(OWC_BN);

extern void  owc_padd(owcrypt *pr_owc,  OWC_BN,OWC_BN,OWC_BN);
extern void  owc_psub(owcrypt *pr_owc,  OWC_BN,OWC_BN,OWC_BN);
extern void  owc_pmul(owcrypt *pr_owc,  OWC_BN,owc_small,OWC_BN);
extern owc_small owc_sdiv(owcrypt *pr_owc, OWC_BN,owc_small,OWC_BN);

extern void  owc_shift(owcrypt *pr_owc,  OWC_BN,int,OWC_BN);
extern owcrypt *owc_first_alloc(void);
extern void  *owc_alloc(owcrypt *pr_owc,  int,int);
extern void  owc_free(void *);  

extern int   owc_testbit(owcrypt *pr_owc,  OWC_BN,int);

extern int   owc_naf_window(owcrypt *pr_owc,  OWC_BN,OWC_BN,int,int *,int *,int);




extern owc_small muldiv(owc_small,owc_small,owc_small,owc_small,owc_small *);
extern owc_small muldvm(owc_small,owc_small,owc_small,owc_small *); 
extern owc_small muldvd(owc_small,owc_small,owc_small,owc_small *); 
extern void     muldvd2(owc_small,owc_small,owc_small *,owc_small *); 

extern OWC_BN owcvar_mem_variable(char *,int,int);
extern owc_point* epoint_init_mem_variable( char *,int,int);


extern owc_small sgcd(owc_small,owc_small);

extern void  zero(OWC_BN);
extern void  convert(owcrypt *pr_owc, int,OWC_BN);
extern void  uconvert( owcrypt *pr_owc,unsigned int,OWC_BN);

extern OWC_BN bignum_init(owcrypt *pr_owc);
extern OWC_BN owcvar_mem(owcrypt *pr_owc, char *,int);
extern void  bignum_clear(OWC_BN);
extern void  *memalloc(owcrypt *pr_owc,  int);
extern void  memkill(owcrypt *pr_owc,  char *,int);

//extern owcrypt *get_owc(void );
extern void  set_owc(owcrypt *);

extern owcrypt *owcsys_init(owcrypt *pr_owc);

extern owcrypt *owcsys_basic(owcrypt *,int,owc_small);

extern int   exsign(OWC_BN);
extern void  insign(int,OWC_BN);
extern int   getdig(owcrypt *pr_owc,  OWC_BN,int);

extern void  copy(OWC_BN,OWC_BN);
extern void  negify(OWC_BN,OWC_BN);
extern void  absol(OWC_BN,OWC_BN);
extern int   size(OWC_BN);
extern int   owc_compare(OWC_BN,OWC_BN);
extern void  add(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);
extern void  subtract(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);
extern void  incr(owcrypt *pr_owc, OWC_BN,int,OWC_BN);
extern void  decr(owcrypt *pr_owc,  OWC_BN,int,OWC_BN);
extern void  premult(owcrypt *pr_owc,  OWC_BN,int,OWC_BN);
extern int   subdiv(owcrypt *pr_owc, OWC_BN,int,OWC_BN);
extern BOOL  subdivisible(owcrypt *pr_owc, OWC_BN,int);
extern int   remain(owcrypt *pr_owc, OWC_BN,int);
extern void  bytes_to_big(owcrypt *pr_owc, int,const char *,OWC_BN);
extern int   big_to_bytes(owcrypt *pr_owc, int,OWC_BN,char *,BOOL);
//extern owc_small normalise(owcrypt *pr_owc, OWC_BN,OWC_BN);
extern void  multiply(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);

extern void  divide(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);
extern BOOL  divisible(owcrypt *pr_owc, OWC_BN,OWC_BN);
extern void  mad(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN,OWC_BN,OWC_BN,OWC_BN);

extern owc_point* epoint_init(owcrypt *pr_owc );
extern owc_point* epoint_init_mem(owcrypt *pr_owc,  char *,int);
extern void* ecp_memalloc(owcrypt *pr_owc,  int);
void ecp_memkill(owcrypt *pr_owc,  char *,int);
BOOL init_big_from_rom(OWC_BN,int,const owc_small *,int ,int *);
BOOL init_point_from_rom(owc_point *,int,const owc_small *,int,int *);

/* Group 2 - Advanced arithmetic routines */


extern int   invmodp(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);
extern int   logb2( owcrypt *pr_owc,OWC_BN);

extern void  expb2( owcrypt *pr_owc,int,OWC_BN);


extern void  powmod(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN,OWC_BN);




/* Montgomery stuff */

extern owc_small prepare_monty(owcrypt *pr_owc, OWC_BN);
extern void  kill_monty(owcrypt *pr_owc );
extern void  nres(owcrypt *pr_owc, OWC_BN,OWC_BN);
extern void  redc(owcrypt *pr_owc, OWC_BN,OWC_BN);

extern void  nres_negate(owcrypt *pr_owc, OWC_BN,OWC_BN);
extern void  nres_modadd(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);
extern void  nres_modsub(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);
extern void  nres_lazy( OWC_BN,OWC_BN,OWC_BN,OWC_BN,OWC_BN,OWC_BN);
extern void  nres_complex(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN,OWC_BN);
extern void  nres_double_modadd( OWC_BN,OWC_BN,OWC_BN);
extern void  nres_double_modsub( OWC_BN,OWC_BN,OWC_BN);
extern void  nres_premult(owcrypt *pr_owc, OWC_BN,int,OWC_BN);
extern void  nres_modmult(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);
extern int   nres_moddiv(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);

extern void  nres_powmod(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);


extern BOOL  nres_double_inverse(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN,OWC_BN);
extern BOOL  nres_multi_inverse(owcrypt *pr_owc, int,OWC_BN *,OWC_BN *);



/* elliptic curve stuff */

extern BOOL point_at_infinity(owc_point *);

extern void owc_jsf( OWC_BN,OWC_BN,OWC_BN,OWC_BN,OWC_BN,OWC_BN);

extern void ecurve_init(owcrypt *pr_owc, OWC_BN,OWC_BN,OWC_BN);
extern int  ecurve_add(owcrypt *pr_owc, owc_point *,owc_point *);
extern int  ecurve_sub( owcrypt *pr_owc,owc_point *,owc_point *);
extern void ecurve_double_add(owcrypt *pr_owc, owc_point *,owc_point *,owc_point *,owc_point *,OWC_BN *,OWC_BN *);
extern void ecurve_multi_add(owcrypt *pr_owc, int,owc_point **,owc_point **);
extern void ecurve_double(owcrypt *pr_owc, owc_point*);
extern int  ecurve_mult(owcrypt *pr_owc, OWC_BN,owc_point *,owc_point *);

extern void ecurve_multn(owcrypt *pr_owc, int,OWC_BN *,owc_point**,owc_point *);

extern BOOL epoint_x( OWC_BN);
extern BOOL epoint_set(owcrypt *pr_owc, OWC_BN,OWC_BN,owc_point*);
extern int  epoint_get(owcrypt *pr_owc, owc_point*,OWC_BN,OWC_BN);
extern void epoint_getxyz( owc_point *,OWC_BN,OWC_BN,OWC_BN);
extern BOOL epoint_norm( owc_point *);
extern BOOL epoint_multi_norm( int,OWC_BN *,owc_point **);
extern void epoint_free(owc_point *);
extern void epoint_copy(owc_point *,owc_point *);
extern BOOL epoint_comp( owc_point *,owc_point *);
extern void epoint_negate(owcrypt *pr_owc, owc_point *);

#endif


