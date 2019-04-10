

#include <stdlib.h> 
#include "owcrypt_core.h"


static void epoint_getrhs(owcrypt *pr_owc, OWC_BN x,OWC_BN y)
{
    nres_modmult(pr_owc, x,x,y);
    nres_modmult(pr_owc, y,x,y);
    if (owc_abs(pr_owc->Asize)==OWC_TOOBIG)
        nres_modmult(pr_owc, x,pr_owc->A,pr_owc->tmp1);
    else
        nres_premult(pr_owc, x,pr_owc->Asize,pr_owc->tmp1);
    nres_modadd(pr_owc, y,pr_owc->tmp1,y);
    if (owc_abs(pr_owc->Bsize)==OWC_TOOBIG)
        nres_modadd(pr_owc, y,pr_owc->B,y);
    else
    {
        convert(pr_owc, pr_owc->Bsize,pr_owc->tmp1);
        nres(pr_owc, pr_owc->tmp1,pr_owc->tmp1);
        nres_modadd(pr_owc, y,pr_owc->tmp1,y);
    }
}

BOOL epoint_set(owcrypt *pr_owc, OWC_BN x,OWC_BN y,owc_point *p)
{
    BOOL valid;
    if (x==NULL || y==NULL)
    {
        copy(pr_owc->one,p->X);
        copy(pr_owc->one,p->Y);
        p->marker=OWC_POINT_INFINITY;
        return TRUE;
    }
    nres(pr_owc, x,p->X);

    epoint_getrhs(pr_owc, p->X,pr_owc->tmp3);

    valid=FALSE;
    nres(pr_owc, y,p->Y);
    nres_modmult(pr_owc, p->Y,p->Y,pr_owc->tmp1);
    if (owc_compare(pr_owc->tmp1,pr_owc->tmp3)==0)
        valid=TRUE;
    if (valid)
    {
        p->marker=OWC_POINT_NORMALIZED;
        return TRUE;
    }
    return FALSE;
}

int epoint_get(owcrypt *pr_owc, owc_point* p,OWC_BN x,OWC_BN y)
{
    int lsb;
    if (p->marker==OWC_POINT_INFINITY)
    {
        zero(x);
        zero(y);
        return 0;
    }
    redc(pr_owc, p->X,x);
    redc(pr_owc, p->Y,pr_owc->tmp1);
    if (x!=y)
        copy(pr_owc->tmp1,y);
    lsb=remain(pr_owc, pr_owc->tmp1,2);
    return lsb;
}
void ecurve_double_add(owcrypt *pr_owc, owc_point *a,owc_point*b,owc_point *c,owc_point *d,OWC_BN *s1,OWC_BN *s2)
{
    if (a->marker==OWC_POINT_INFINITY || size(a->Y)==0)
    {
        *s1=NULL;
        ecurve_add(pr_owc, c,d);
        *s2=pr_owc->tmp8;
        return;
    }
    if (b->marker==OWC_POINT_INFINITY || size(b->Y)==0)
    {
        *s1=NULL;
        epoint_copy(a,b);
        ecurve_add(pr_owc, c,d);
        *s2=pr_owc->tmp8;
        return;
    }
    if (c->marker==OWC_POINT_INFINITY || size(c->Y)==0)
    {
        ecurve_add(pr_owc, a,b);
        *s1=pr_owc->tmp8;
        *s2=NULL;
        return;
    }
    if (d->marker==OWC_POINT_INFINITY || size(d->Y)==0)
    {
        epoint_copy(c,d);
        ecurve_add(pr_owc, a,b);
        *s1=pr_owc->tmp8;
        *s2=NULL;
        return;
    }

    if (a==b || (owc_compare(a->X,b->X)==0 && owc_compare(a->Y,b->Y)==0))
    {
        nres_modmult(pr_owc, a->X,a->X,pr_owc->tmp8);
        nres_premult(pr_owc, pr_owc->tmp8,3,pr_owc->tmp8);
        if (owc_abs(pr_owc->Asize)==OWC_TOOBIG)
            nres_modadd(pr_owc, pr_owc->tmp8,pr_owc->A,pr_owc->tmp8);
        else
        {
            convert(pr_owc, pr_owc->Asize,pr_owc->tmp2);
            nres(pr_owc, pr_owc->tmp2,pr_owc->tmp2);
            nres_modadd(pr_owc, pr_owc->tmp8,pr_owc->tmp2,pr_owc->tmp8);
        }
        nres_premult(pr_owc, a->Y,2,pr_owc->tmp10);
    }
    else
    {
        if (owc_compare(a->X,b->X)==0)
        {
            epoint_set(pr_owc, NULL,NULL,b);
            *s1=NULL;
            ecurve_add(pr_owc, c,d);
            *s2=pr_owc->tmp8;
            return;
        }
        nres_modsub(pr_owc, a->Y,b->Y,pr_owc->tmp8);
        nres_modsub(pr_owc, a->X,b->X,pr_owc->tmp10);
    }

    if (c==d || (owc_compare(c->X,d->X)==0 && owc_compare(c->Y,d->Y)==0))
    {
        nres_modmult(pr_owc, c->X,c->X,pr_owc->tmp9);
        nres_premult(pr_owc, pr_owc->tmp9,3,pr_owc->tmp9); /* 3x^2 */
        if (owc_abs(pr_owc->Asize)==OWC_TOOBIG)
            nres_modadd(pr_owc, pr_owc->tmp9,pr_owc->A,pr_owc->tmp9);
        else
        {
            convert(pr_owc, pr_owc->Asize,pr_owc->tmp2);
            nres(pr_owc, pr_owc->tmp2,pr_owc->tmp2);
            nres_modadd(pr_owc, pr_owc->tmp9,pr_owc->tmp2,pr_owc->tmp9);
        }
        nres_premult(pr_owc, c->Y,2,pr_owc->tmp11);
    }
    else
    {
        if (owc_compare(c->X,d->X)==0)
        {
            epoint_set(pr_owc, NULL,NULL,d);
            *s2=NULL;
            ecurve_add(pr_owc, a,b);
            *s1=pr_owc->tmp8;
            return;
        }
        nres_modsub(pr_owc, c->Y,d->Y,pr_owc->tmp9);
        nres_modsub(pr_owc, c->X,d->X,pr_owc->tmp11);
    }

    nres_double_inverse(pr_owc, pr_owc->tmp10,pr_owc->tmp10,pr_owc->tmp11,pr_owc->tmp11);
    nres_modmult(pr_owc, pr_owc->tmp8,pr_owc->tmp10,pr_owc->tmp8);
    nres_modmult(pr_owc, pr_owc->tmp9,pr_owc->tmp11,pr_owc->tmp9);
    nres_modmult(pr_owc, pr_owc->tmp8,pr_owc->tmp8,pr_owc->tmp2);
    nres_modsub(pr_owc, pr_owc->tmp2,a->X,pr_owc->tmp1);
    nres_modsub(pr_owc, pr_owc->tmp1,b->X,pr_owc->tmp1);
    nres_modsub(pr_owc, b->X,pr_owc->tmp1,pr_owc->tmp2);
    nres_modmult(pr_owc, pr_owc->tmp2,pr_owc->tmp8,pr_owc->tmp2);
    nres_modsub(pr_owc, pr_owc->tmp2,b->Y,b->Y);
    copy(pr_owc->tmp1,b->X);
    b->marker=OWC_POINT_GENERAL;
    nres_modmult(pr_owc, pr_owc->tmp9,pr_owc->tmp9,pr_owc->tmp2); /* m^2 */
    nres_modsub(pr_owc, pr_owc->tmp2,c->X,pr_owc->tmp1);
    nres_modsub(pr_owc, pr_owc->tmp1,d->X,pr_owc->tmp1);
    nres_modsub(pr_owc, d->X,pr_owc->tmp1,pr_owc->tmp2);
    nres_modmult(pr_owc, pr_owc->tmp2,pr_owc->tmp9,pr_owc->tmp2);
    nres_modsub(pr_owc, pr_owc->tmp2,d->Y,d->Y);
    copy(pr_owc->tmp1,d->X);
    d->marker=OWC_POINT_GENERAL;
    *s1=pr_owc->tmp8;
    *s2=pr_owc->tmp9;
}

void ecurve_multi_add(owcrypt *pr_owc, int m,owc_point **x,owc_point**w)
{
    int i,*flag;
    OWC_BN *A,*B,*C;

    A=(OWC_BN *)owc_alloc(pr_owc, m,sizeof(OWC_BN));
    B=(OWC_BN *)owc_alloc(pr_owc, m,sizeof(OWC_BN));
    C=(OWC_BN *)owc_alloc(pr_owc, m,sizeof(OWC_BN));
    flag=(int *)owc_alloc(pr_owc, m,sizeof(int));

    copy(pr_owc->one,pr_owc->tmp3);

    for (i=0;i<m;i++)
    {
        A[i]=bignum_init(pr_owc);
        B[i]=bignum_init(pr_owc);
        C[i]=bignum_init(pr_owc);
        flag[i]=0;
        if (owc_compare(x[i]->X,w[i]->X)==0 && owc_compare(x[i]->Y,w[i]->Y)==0)
        {
            if (x[i]->marker==OWC_POINT_INFINITY || size(x[i]->Y)==0)
            {
                flag[i]=1;
                copy(pr_owc->tmp3,B[i]);
                continue;
            }
            nres_modmult(pr_owc, x[i]->X,x[i]->X,A[i]);
            nres_premult(pr_owc, A[i],3,A[i]);
            if (owc_abs(pr_owc->Asize) == OWC_TOOBIG)
                nres_modadd(pr_owc, A[i],pr_owc->A,A[i]);
            else
            {
                convert(pr_owc, pr_owc->Asize,pr_owc->tmp2);
                nres(pr_owc, pr_owc->tmp2,pr_owc->tmp2);
                nres_modadd(pr_owc, A[i],pr_owc->tmp2,A[i]);
            }
            nres_premult(pr_owc, x[i]->Y,2,B[i]);
        }
        else
        {
            if (x[i]->marker==OWC_POINT_INFINITY)
            {
                flag[i]=2;
                copy(pr_owc->tmp3,B[i]);
                continue;
            }
            if (w[i]->marker==OWC_POINT_INFINITY)
            {
                flag[i]=3;
                copy(pr_owc->tmp3,B[i]);
                continue;
            }
            nres_modsub(pr_owc, x[i]->X,w[i]->X,B[i]);
            if (size(B[i])==0)
            {
                flag[i]=1;
                copy(pr_owc->tmp3,B[i]);
                continue;
            }
            nres_modsub(pr_owc, x[i]->Y,w[i]->Y,A[i]);
        }
    }
    nres_multi_inverse(pr_owc, m,B,C);
    for (i=0;i<m;i++)
    {
        if (flag[i]==1)
        {
            epoint_set(pr_owc, NULL,NULL,w[i]);
            continue;
        }
        if (flag[i]==2)
        {
            continue;
        }
        if (flag[i]==3)
        {
            epoint_copy(x[i],w[i]);
            continue;
        }
        nres_modmult(pr_owc, A[i],C[i],pr_owc->tmp8);

        nres_modmult(pr_owc, pr_owc->tmp8,pr_owc->tmp8,pr_owc->tmp2);
        nres_modsub(pr_owc, pr_owc->tmp2,x[i]->X,pr_owc->tmp1);
        nres_modsub(pr_owc, pr_owc->tmp1,w[i]->X,pr_owc->tmp1);
   
        nres_modsub(pr_owc, w[i]->X,pr_owc->tmp1,pr_owc->tmp2);
        nres_modmult(pr_owc, pr_owc->tmp2,pr_owc->tmp8,pr_owc->tmp2);
        nres_modsub(pr_owc, pr_owc->tmp2,w[i]->Y,w[i]->Y);
        copy(pr_owc->tmp1,w[i]->X);
        w[i]->marker=OWC_POINT_NORMALIZED;

        owc_free(C[i]);
        owc_free(B[i]);
        owc_free(A[i]);
    }
    owc_free(flag);
    owc_free(C); owc_free(B); owc_free(A);
}

void ecurve_double(owcrypt *pr_owc, owc_point *p)
{
    if (p->marker==OWC_POINT_INFINITY) 
    {
        return;
    }
    if (size(p->Y)==0)
    {
        epoint_set(pr_owc, NULL,NULL,p);
        return;
    }

    nres_modmult(pr_owc, p->X,p->X,pr_owc->tmp8);
    nres_premult(pr_owc, pr_owc->tmp8,3,pr_owc->tmp8);
    if (owc_abs(pr_owc->Asize) == OWC_TOOBIG)
        nres_modadd(pr_owc, pr_owc->tmp8,pr_owc->A,pr_owc->tmp8);
    else
    {
        convert(pr_owc, pr_owc->Asize,pr_owc->tmp2);
        nres(pr_owc, pr_owc->tmp2,pr_owc->tmp2);
        nres_modadd(pr_owc, pr_owc->tmp8,pr_owc->tmp2,pr_owc->tmp8);
    }
    nres_premult(pr_owc, p->Y,2,pr_owc->tmp6);
    if (nres_moddiv(pr_owc, pr_owc->tmp8,pr_owc->tmp6,pr_owc->tmp8)>1)
    {
        epoint_set(pr_owc, NULL,NULL,p);
        return;
    }
    nres_modmult(pr_owc, pr_owc->tmp8,pr_owc->tmp8,pr_owc->tmp2);
    nres_premult(pr_owc, p->X,2,pr_owc->tmp1);
    nres_modsub(pr_owc, pr_owc->tmp2,pr_owc->tmp1,pr_owc->tmp1);
    nres_modsub(pr_owc, p->X,pr_owc->tmp1,pr_owc->tmp2);
    nres_modmult(pr_owc, pr_owc->tmp2,pr_owc->tmp8,pr_owc->tmp2);
    nres_modsub(pr_owc, pr_owc->tmp2,p->Y,p->Y);
    copy(pr_owc->tmp1,p->X);
    return;
}
   
static BOOL ecurve_padd(owcrypt *pr_owc, owc_point *p,owc_point *pa)
{
    nres_modsub(pr_owc, p->Y,pa->Y,pr_owc->tmp8);
    nres_modsub(pr_owc, p->X,pa->X,pr_owc->tmp6);
    if (size(pr_owc->tmp6)==0)
    {
        if (size(pr_owc->tmp8)==0)
        {
            return FALSE;
        }
        else
        {
            epoint_set(pr_owc, NULL,NULL,pa);
            return TRUE;
        }
    }
    if (nres_moddiv(pr_owc, pr_owc->tmp8,pr_owc->tmp6,pr_owc->tmp8)>1)
    {
        epoint_set(pr_owc, NULL,NULL,pa);
        return TRUE;
    }
    nres_modmult(pr_owc, pr_owc->tmp8,pr_owc->tmp8,pr_owc->tmp2); /* w2=m^2 */
    nres_modsub(pr_owc, pr_owc->tmp2,p->X,pr_owc->tmp1); /* w1=m^2-x1-x2 */
    nres_modsub(pr_owc, pr_owc->tmp1,pa->X,pr_owc->tmp1);
    nres_modsub(pr_owc, pa->X,pr_owc->tmp1,pr_owc->tmp2);
    nres_modmult(pr_owc, pr_owc->tmp2,pr_owc->tmp8,pr_owc->tmp2);
    nres_modsub(pr_owc, pr_owc->tmp2,pa->Y,pa->Y);
    copy(pr_owc->tmp1,pa->X);
    pa->marker=OWC_POINT_NORMALIZED;
    return TRUE;
}

void epoint_copy(owc_point *a,owc_point *b)
{   
    if (a==b || b==NULL)
        return;
    copy(a->X,b->X);
    copy(a->Y,b->Y);
    b->marker=a->marker;
    return;
}

BOOL epoint_comp( owc_point *a,owc_point *b)
{
    BOOL result;

    if (a==b)
        return TRUE;
    if (a->marker==OWC_POINT_INFINITY)
    {
        if (b->marker==OWC_POINT_INFINITY)
            return TRUE;
        else
            return FALSE;
    }
    if (b->marker==OWC_POINT_INFINITY)
        return FALSE;
        if (owc_compare(a->X,b->X)==0 && owc_compare(a->Y,b->Y)==0)
            result=TRUE;
        else
            result=FALSE;
        return result;
}

int ecurve_add(owcrypt *pr_owc, owc_point *p,owc_point *pa)
{
    if (p==pa) 
    {
        ecurve_double(pr_owc, pa);
        if (pa->marker==OWC_POINT_INFINITY)
            return OWC_PASS;
        return OWC_DOUBLE;
    }
    if (pa->marker==OWC_POINT_INFINITY)
    {
        epoint_copy(p,pa);
        return OWC_ADD;
    }
    if (p->marker==OWC_POINT_INFINITY) 
    {
        return OWC_ADD;
    }
    if (!ecurve_padd(pr_owc, p,pa))
    {    
        ecurve_double(pr_owc, pa);
        return OWC_DOUBLE;
    }
    if (pa->marker==OWC_POINT_INFINITY)
        return OWC_PASS;
    return OWC_ADD;
}

void epoint_negate(owcrypt *pr_owc, owc_point *p)
{
    if (p->marker==OWC_POINT_INFINITY)
        return;
    if (size(p->Y)!=0) owc_psub(pr_owc, pr_owc->modulus,p->Y,p->Y);

}

int ecurve_sub(owcrypt *pr_owc, owc_point *p,owc_point *pa)
{
    int r;
    if (p==pa)
    {
        epoint_set(pr_owc, NULL,NULL,pa);
        return OWC_PASS;
    } 
    if (p->marker==OWC_POINT_INFINITY) 
    {
        return OWC_ADD;
    }

    epoint_negate(pr_owc, p);
    r=ecurve_add(pr_owc, p,pa);
    epoint_negate(pr_owc, p);
    return r;
}

int ecurve_mult(owcrypt *pr_owc, OWC_BN e,owc_point *pa,owc_point *pt)
{
    int i,j,n,nb,nbs,nzs,nadds;
    owc_point *table[OWC_CURVE_LEN_WORD];
    char *mem;
    owc_point *p;
    int ce,ch;
    if (size(e)==0) 
    {
        epoint_set(pr_owc, NULL,NULL,pt);
        return 0;
    }
    copy(e,pr_owc->tmp9);
    epoint_copy(pa,pt);

    if (size(pr_owc->tmp9)<0)
    {
        negify(pr_owc->tmp9,pr_owc->tmp9);
        epoint_negate(pr_owc, pt);
    }
    if (size(pr_owc->tmp9)==1)
    {
        return 0;
    }
    premult(pr_owc, pr_owc->tmp9,3,pr_owc->tmp10);
    if (pr_owc->base==pr_owc->base2)
    {
        mem=(char *)ecp_memalloc(pr_owc, OWC_CURVE_LEN_WORD);
        for (i=0;i<=OWC_CURVE_LEN_WORD-1;i++)
        {
            table[i]=epoint_init_mem(pr_owc, mem,i);
        }
        epoint_copy(pt,table[0]);
        epoint_copy(table[0],table[OWC_CURVE_LEN_WORD-1]);
        ecurve_double(pr_owc, table[OWC_CURVE_LEN_WORD-1]);
        for (i=1;i<OWC_CURVE_LEN_WORD-1;i++)
        {
            epoint_copy(table[i-1],table[i]);
            ecurve_add(pr_owc, table[OWC_CURVE_LEN_WORD-1],table[i]);
        }
        ecurve_add(pr_owc, table[OWC_CURVE_LEN_WORD-2],table[OWC_CURVE_LEN_WORD-1]);
        nb=logb2(pr_owc, pr_owc->tmp10);
        nadds=0;
        epoint_set(pr_owc, NULL,NULL,pt);
        for (i=nb-1;i>=1;)
        {
            n=owc_naf_window(pr_owc, pr_owc->tmp9,pr_owc->tmp10,i,&nbs,&nzs,OWC_CURVE_LEN_WORD);
            for (j=0;j<nbs;j++)
                ecurve_double(pr_owc, pt);
            if (n>0)
            {
                ecurve_add(pr_owc, table[n/2],pt);
                nadds++;
                
            }
            if (n<0)
            {
                ecurve_sub(pr_owc, table[(-n)/2],pt);
                nadds++;
                
            }
            i-=nbs;
            if (nzs)
            {
                for (j=0;j<nzs;j++)
                    ecurve_double(pr_owc, pt);
                i-=nzs;
            }
        }
        ecp_memkill(pr_owc, mem,OWC_CURVE_LEN_WORD);
    }
    else
    { 
        mem=(char *)ecp_memalloc(pr_owc, 1);
        p=epoint_init_mem(pr_owc, mem,0);
        epoint_copy(pt,p);
        nadds=0;
        expb2(pr_owc, logb2(pr_owc, pr_owc->tmp10)-1,pr_owc->tmp11);
        owc_psub(pr_owc, pr_owc->tmp10,pr_owc->tmp11,pr_owc->tmp10);
        subdiv(pr_owc, pr_owc->tmp11,2,pr_owc->tmp11);
        while (size(pr_owc->tmp11) > 1)
        {
            ecurve_double(pr_owc, pt);
            ce=owc_compare(pr_owc->tmp9,pr_owc->tmp11);
            ch=owc_compare(pr_owc->tmp10,pr_owc->tmp11);
            if (ch>=0) 
            {
                if (ce<0)
                {
                    ecurve_add(pr_owc, p,pt);
                    nadds++;
                    
                }
                owc_psub(pr_owc, pr_owc->tmp10,pr_owc->tmp11,pr_owc->tmp10);
            }
            if (ce>=0) 
            {
                if (ch<0)
                {
                    ecurve_sub(pr_owc, p,pt);
                    nadds++;
                    
                }
                owc_psub(pr_owc, pr_owc->tmp9,pr_owc->tmp11,pr_owc->tmp9);
            }
            subdiv(pr_owc, pr_owc->tmp11,2,pr_owc->tmp11);
        }
        ecp_memkill(pr_owc, mem,1);
    }
    return nadds;
}

void ecurve_multn(owcrypt *pr_owc, int n,OWC_BN *y,owc_point **x,owc_point *w)
{
    int i,j,k,m,nb,ea;
    owc_point **G;
    m=1<<n;
    G=(owc_point **)owc_alloc(pr_owc, m,sizeof(owc_point*));

    for (i=0,k=1;i<n;i++)
    {
        for (j=0; j < (1<<i) ;j++)
        {
            G[k]=epoint_init( pr_owc);
            epoint_copy(x[i],G[k]);
            if (j!=0)
                ecurve_add(pr_owc, G[j],G[k]);
            k++;
        }
    }

    nb=0;
    for (j=0;j<n;j++) if ((k=logb2(pr_owc, y[j])) > nb)
        nb=k;

    epoint_set(pr_owc, NULL,NULL,w);

    if (pr_owc->base==pr_owc->base2)
    {
        for (i=nb-1;i>=0;i--)
        {
            ea=0;
            k=1;
            for (j=0;j<n;j++)
            {
                if (owc_testbit(pr_owc, y[j],i))
                    ea+=k;
                k<<=1;
            }
            ecurve_double(pr_owc, w);
            if (ea!=0)
                ecurve_add(pr_owc, G[ea],w);
        }
    }
    else ;

    for (i=1;i<m;i++) epoint_free(G[i]);
    owc_free(G);
}

BOOL ecurve_add_sub(owcrypt *pr_owc, owc_point *P,owc_point *Q,owc_point *PP,owc_point *PM)
{
    OWC_BN t1,t2,lam;

    if (P->marker==OWC_POINT_GENERAL || Q->marker==OWC_POINT_GENERAL)
    {
        return FALSE;
    }

    if (owc_compare(P->X,Q->X)==0)
    {
        epoint_copy(P,PP);
        ecurve_add(pr_owc, Q,PP);
        epoint_copy(P,PM);
        ecurve_sub(pr_owc, Q,PM);
        return TRUE;
    }

    t1= pr_owc->tmp10;
    t2= pr_owc->tmp11; 
    lam = pr_owc->tmp13;   

    copy(P->X,t2);
    nres_modsub(pr_owc, t2,Q->X,t2);

    redc(pr_owc, t2,t2);
    invmodp(pr_owc, t2,pr_owc->modulus,t2);
    nres(pr_owc, t2,t2);
    
    nres_modadd(pr_owc, P->X,Q->X,PP->X);
    copy(PP->X,PM->X);

    copy(P->Y,t1);
    nres_modsub(pr_owc, t1,Q->Y,t1);
    copy(t1,lam);
    nres_modmult(pr_owc, lam,t2,lam);
    copy(lam,t1);
    nres_modmult(pr_owc, t1,t1,t1);
    nres_modsub(pr_owc, t1,PP->X,PP->X);
    copy(Q->X,PP->Y);
    nres_modsub(pr_owc, PP->Y,PP->X,PP->Y);
    nres_modmult(pr_owc, PP->Y,lam,PP->Y);
    nres_modsub(pr_owc, PP->Y,Q->Y,PP->Y);

    copy(P->Y,t1);
    nres_modadd(pr_owc, t1,Q->Y,t1);
    copy(t1,lam);
    nres_modmult(pr_owc, lam,t2,lam);
    copy(lam,t1);
    nres_modmult(pr_owc, t1,t1,t1);
    nres_modsub(pr_owc, t1,PM->X,PM->X);
    copy(Q->X,PM->Y);
    nres_modsub(pr_owc, PM->Y,PM->X,PM->Y);
    nres_modmult(pr_owc, PM->Y,lam,PM->Y);
    nres_modadd(pr_owc, PM->Y,Q->Y,PM->Y);

    PP->marker=OWC_POINT_NORMALIZED;
    PM->marker=OWC_POINT_NORMALIZED;

    return TRUE;
}
