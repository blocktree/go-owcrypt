#include "ref10_ge.h"

/*
r = p + q
*/

void REF10_ge_madd(REF10_ge_p1p1 *r,const REF10_ge_p3 *p,const REF10_ge_precomp *q)
{
  REF10_fe t0;

    /* qhasm: enter REF10_ge_madd */
    
    /* qhasm: REF10_fe X1 */
    
    /* qhasm: REF10_fe Y1 */
    
    /* qhasm: REF10_fe Z1 */
    
    /* qhasm: REF10_fe T1 */
    
    /* qhasm: REF10_fe ypx2 */
    
    /* qhasm: REF10_fe ymx2 */
    
    /* qhasm: REF10_fe xy2d2 */
    
    /* qhasm: REF10_fe X3 */
    
    /* qhasm: REF10_fe Y3 */
    
    /* qhasm: REF10_fe Z3 */
    
    /* qhasm: REF10_fe T3 */
    
    /* qhasm: REF10_fe YpX1 */
    
    /* qhasm: REF10_fe YmX1 */
    
    /* qhasm: REF10_fe A */
    
    /* qhasm: REF10_fe B */
    
    /* qhasm: REF10_fe C */
    
    /* qhasm: REF10_fe D */
    
    /* qhasm: YpX1 = Y1+X1 */
    /* asm 1: REF10_fe_add(>YpX1=fe#1,<Y1=fe#12,<X1=fe#11); */
    /* asm 2: REF10_fe_add(>YpX1=r->X,<Y1=p->Y,<X1=p->X); */
    REF10_fe_add(r->X,p->Y,p->X);
    
    /* qhasm: YmX1 = Y1-X1 */
    /* asm 1: REF10_fe_sub(>YmX1=fe#2,<Y1=fe#12,<X1=fe#11); */
    /* asm 2: REF10_fe_sub(>YmX1=r->Y,<Y1=p->Y,<X1=p->X); */
    REF10_fe_sub(r->Y,p->Y,p->X);
    
    /* qhasm: A = YpX1*ypx2 */
    /* asm 1: REF10_fe_mul(>A=fe#3,<YpX1=fe#1,<ypx2=fe#15); */
    /* asm 2: REF10_fe_mul(>A=r->Z,<YpX1=r->X,<ypx2=q->yplusx); */
    REF10_fe_mul(r->Z,r->X,q->yplusx);
    
    /* qhasm: B = YmX1*ymx2 */
    /* asm 1: REF10_fe_mul(>B=fe#2,<YmX1=fe#2,<ymx2=fe#16); */
    /* asm 2: REF10_fe_mul(>B=r->Y,<YmX1=r->Y,<ymx2=q->yminusx); */
    REF10_fe_mul(r->Y,r->Y,q->yminusx);
    
    /* qhasm: C = xy2d2*T1 */
    /* asm 1: REF10_fe_mul(>C=fe#4,<xy2d2=fe#17,<T1=fe#14); */
    /* asm 2: REF10_fe_mul(>C=r->T,<xy2d2=q->xy2d,<T1=p->T); */
    REF10_fe_mul(r->T,q->xy2d,p->T);
    
    /* qhasm: D = 2*Z1 */
    /* asm 1: REF10_fe_add(>D=fe#5,<Z1=fe#13,<Z1=fe#13); */
    /* asm 2: REF10_fe_add(>D=t0,<Z1=p->Z,<Z1=p->Z); */
    REF10_fe_add(t0,p->Z,p->Z);
    
    /* qhasm: X3 = A-B */
    /* asm 1: REF10_fe_sub(>X3=fe#1,<A=fe#3,<B=fe#2); */
    /* asm 2: REF10_fe_sub(>X3=r->X,<A=r->Z,<B=r->Y); */
    REF10_fe_sub(r->X,r->Z,r->Y);
    
    /* qhasm: Y3 = A+B */
    /* asm 1: REF10_fe_add(>Y3=fe#2,<A=fe#3,<B=fe#2); */
    /* asm 2: REF10_fe_add(>Y3=r->Y,<A=r->Z,<B=r->Y); */
    REF10_fe_add(r->Y,r->Z,r->Y);
    
    /* qhasm: Z3 = D+C */
    /* asm 1: REF10_fe_add(>Z3=fe#3,<D=fe#5,<C=fe#4); */
    /* asm 2: REF10_fe_add(>Z3=r->Z,<D=t0,<C=r->T); */
    REF10_fe_add(r->Z,t0,r->T);
    
    /* qhasm: T3 = D-C */
    /* asm 1: REF10_fe_sub(>T3=fe#4,<D=fe#5,<C=fe#4); */
    /* asm 2: REF10_fe_sub(>T3=r->T,<D=t0,<C=r->T); */
    REF10_fe_sub(r->T,t0,r->T);
    
    /* qhasm: return */

}
