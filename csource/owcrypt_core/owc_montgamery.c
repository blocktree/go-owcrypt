

#include <stdlib.h> 
#include "owcrypt_core.h"

void kill_monty(owcrypt *pr_owc )
{
    zero(pr_owc->modulus);
}

owc_small prepare_monty(owcrypt *pr_owc, OWC_BN n)
{
    if (size(pr_owc->modulus)!=0)
        if (owc_compare(n,pr_owc->modulus)==0)
            return pr_owc->ndash;
    if (size(n)<=2) 
    {
        return (owc_small)0;
    }
    zero(pr_owc->tmp6);
    zero(pr_owc->tmp15);
    pr_owc->pmod8=remain(pr_owc, n,8);
    switch (pr_owc->pmod8)
    {
    case 0:
    case 1:
    case 2:
    case 4:
    case 6:
        pr_owc->qnr=0;
        break;
    case 3:
        pr_owc->qnr=-1;
        break;
    case 5:
        pr_owc->qnr=-2;
        break;
    case 7:
        pr_owc->qnr=-1;
        break;
    }
	pr_owc->pmod9=remain(pr_owc, n,9);

	pr_owc->NO_CARRY=FALSE;
	if (n->w[n->len-1]>>(OWCRYPT - 4) < 5) pr_owc->NO_CARRY=TRUE;
    pr_owc->MONTY=ON;

    convert(pr_owc, 1,pr_owc->one);
    if (!pr_owc->MONTY)
    {
        copy(n,pr_owc->modulus);
        pr_owc->ndash=0;
        return (owc_small)0;
    }

        pr_owc->tmp6->len=2;
        pr_owc->tmp6->w[0]=0;
        pr_owc->tmp6->w[1]=1;
        pr_owc->tmp15->len=1;
        pr_owc->tmp15->w[0]=n->w[0];
        if (invmodp(pr_owc, pr_owc->tmp15,pr_owc->tmp6,pr_owc->tmp14)!=1)
        {
            return (owc_small)0;
        }

    pr_owc->ndash=pr_owc->base-pr_owc->tmp14->w[0];
    copy(n,pr_owc->modulus);
    pr_owc->check=OFF;
    owc_shift(pr_owc, pr_owc->modulus,(int)pr_owc->modulus->len,pr_owc->pR);
    pr_owc->check=ON;
    nres(pr_owc, pr_owc->one,pr_owc->one);
    return pr_owc->ndash;
}

void nres(owcrypt *pr_owc, OWC_BN x,OWC_BN y)
{
    if (size(pr_owc->modulus)==0)
    {
        return;
    }
    copy(x,y);
    divide(pr_owc, y,pr_owc->modulus,pr_owc->modulus);
    if (size(y)<0)
        add(pr_owc, y,pr_owc->modulus,y);
    if (!pr_owc->MONTY) 
    {
        return;
    }
    pr_owc->check=OFF;
    owc_shift(pr_owc, y,(int)pr_owc->modulus->len,pr_owc->tmp0);
    divide(pr_owc, pr_owc->tmp0,pr_owc->modulus,pr_owc->modulus);
    pr_owc->check=ON;
    copy(pr_owc->tmp0,y);
}

void redc(owcrypt *pr_owc, OWC_BN x,OWC_BN y)
{
    owc_small carry,delay_carry,m,ndash,*w0g,*mg;
    int i,j,rn,rn2;
    OWC_BN w0,modulus;
    union doubleword dble;
    owc_large dbled;
    w0=pr_owc->tmp0;
    modulus=pr_owc->modulus;
    ndash=pr_owc->ndash;
    copy(x,w0);
    if (!pr_owc->MONTY)
    {
        divide(pr_owc, w0,modulus,modulus);
        copy(w0,y);
        return;
    }
    delay_carry=0;
    rn=(int)modulus->len;
    rn2=rn+rn;
    if (pr_owc->base==0) 
    {
      mg=modulus->w;
      w0g=w0->w;
      for (i=0;i<rn;i++)
      {
        m=ndash*w0->w[i];
        carry=0;
        for (j=0;j<rn;j++)
        {
            dble.d=(owc_large)m*modulus->w[j]+carry+w0->w[i+j];
            w0->w[i+j]=dble.h[OWC_BOTTOM];
            carry=dble.h[OWC_TOP];
        }
        w0->w[rn+i]+=delay_carry;
        if (w0->w[rn+i]<delay_carry)
            delay_carry=1;
        else
            delay_carry=0;
        w0->w[rn+i]+=carry;
        if (w0->w[rn+i]<carry)
            delay_carry=1;
      }
    }
    else for (i=0;i<rn;i++) 
    {
        muldiv(w0->w[i],ndash,0,pr_owc->base,&m);
        carry=0;
        for (j=0;j<rn;j++)
        {
          dbled=(owc_large)m*modulus->w[j]+carry+w0->w[i+j];
          if (pr_owc->base==pr_owc->base2)
              carry=(owc_small)(dbled>>pr_owc->lg2b);
          else
              carry=(owc_small)(dbled/pr_owc->base);
          w0->w[i+j]=(owc_small)(dbled-(owc_large)carry*pr_owc->base);
        }
        w0->w[rn+i]+=(delay_carry+carry);
        delay_carry=0;
        if (w0->w[rn+i]>=pr_owc->base)
        {
            w0->w[rn+i]-=pr_owc->base;
            delay_carry=1; 
        }
    }
    w0->w[rn2]=delay_carry;
    w0->len=rn2+1;
    owc_shift(pr_owc, w0,(-rn),w0);
    owc_lzero(w0);
    if (owc_compare(w0,modulus)>=0)
        owc_psub(pr_owc, w0,modulus,w0);
    copy(w0,y);
}

void nres_complex(owcrypt *pr_owc, OWC_BN a,OWC_BN b,OWC_BN r,OWC_BN i)
{
	if (pr_owc->NO_CARRY && pr_owc->qnr==-1)
	{
        owc_padd(pr_owc, a,b,pr_owc->tmp1);
        owc_padd(pr_owc, a,pr_owc->modulus,pr_owc->tmp2);
        owc_psub(pr_owc, pr_owc->tmp2,b,pr_owc->tmp2);
        owc_padd(pr_owc, a,a,r);
		nres_modmult(pr_owc, r,b,i);
		nres_modmult(pr_owc, pr_owc->tmp1,pr_owc->tmp2,r);
	}
	else
	{
		nres_modadd(pr_owc, a,b,pr_owc->tmp1);
		nres_modsub(pr_owc, a,b,pr_owc->tmp2);
		if (pr_owc->qnr==-2)
			nres_modsub(pr_owc, pr_owc->tmp2,b,pr_owc->tmp2);
		nres_modmult(pr_owc, a,b,i);
		nres_modmult(pr_owc, pr_owc->tmp1,pr_owc->tmp2,r);
		if (pr_owc->qnr==-2)
			nres_modadd(pr_owc, r,i,r);
		nres_modadd(pr_owc, i,i,i);
	}
}

void nres_negate(owcrypt *pr_owc, OWC_BN x, OWC_BN w)
{
	if (size(x)==0) 
	{
		zero(w);
		return;
	}
    owc_psub(pr_owc, pr_owc->modulus,x,w);
}

void nres_modadd(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN w)
{
    owc_padd(pr_owc, x,y,w);
    if (owc_compare(w,pr_owc->modulus)>=0)
        owc_psub(pr_owc, w,pr_owc->modulus,w);
}

void nres_modsub(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN w)
{
    if (owc_compare(x,y)>=0)
        owc_psub(pr_owc, x,y,w);
    else
    {
        owc_psub(pr_owc, y,x,w);
        owc_psub(pr_owc, pr_owc->modulus,w,w);
    }
}

int nres_moddiv(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN w)
{
    int gcd;
    if (x==y)
    {
        return 0;
    }
    redc(pr_owc, y,pr_owc->tmp6);
    gcd=invmodp(pr_owc, pr_owc->tmp6,pr_owc->modulus,pr_owc->tmp6);
   
    if (gcd!=1)
        zero(w);
    else
    {
        nres(pr_owc, pr_owc->tmp6,pr_owc->tmp6);
        nres_modmult(pr_owc, x,pr_owc->tmp6,w);
    }
    return gcd;
}

void nres_premult(owcrypt *pr_owc, OWC_BN x,int k,OWC_BN w)
{
    int sign=0;
    if (k==0) 
    {
        zero(w);
        return;
    }
    if (k<0)
    {
        k=-k;
        sign=1;
    }
    if (k<=6)
    {
        switch (k)
        {
        case 1: copy(x,w);
                break;
        case 2: nres_modadd(pr_owc, x,x,w);
                break;    
        case 3:
                nres_modadd(pr_owc, x,x,pr_owc->tmp0);
                nres_modadd(pr_owc, x,pr_owc->tmp0,w);
                break;
        case 4:
                nres_modadd(pr_owc, x,x,w);
                nres_modadd(pr_owc, w,w,w);
                break;    
        case 5:
                nres_modadd(pr_owc, x,x,pr_owc->tmp0);
                nres_modadd(pr_owc, pr_owc->tmp0,pr_owc->tmp0,pr_owc->tmp0);
                nres_modadd(pr_owc, x,pr_owc->tmp0,w);
                break;
        case 6:
                nres_modadd(pr_owc, x,x,w);
                nres_modadd(pr_owc, w,w,pr_owc->tmp0);
                nres_modadd(pr_owc, w,pr_owc->tmp0,w);
                break;
        }
        if (sign==1) nres_negate(pr_owc, w,w);
        return;
    }

    owc_pmul(pr_owc, x,(owc_small)k,pr_owc->tmp0);
    divide(pr_owc, pr_owc->tmp0,pr_owc->modulus,pr_owc->modulus);
	copy(pr_owc->tmp0,w);
    if (sign==1) nres_negate(pr_owc, w,w);
}

void nres_modmult(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN w)
{
    if ((x==NULL || x->len==0) && x==w)
        return;
    if ((y==NULL || y->len==0) && y==w)
        return;
    if (y==NULL || x==NULL || x->len==0 || y->len==0)
    {
        zero(w);
        return;
    }

    pr_owc->check=OFF;
    multiply(pr_owc, x,y,pr_owc->tmp0);
    redc(pr_owc, pr_owc->tmp0,w);
    pr_owc->check=ON;
}

BOOL nres_double_inverse(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN w,OWC_BN z)
{
    nres_modmult(pr_owc, x,w,pr_owc->tmp6);

    if (size(pr_owc->tmp6)==0)
    {
        return FALSE;
    }
    redc(pr_owc, pr_owc->tmp6,pr_owc->tmp6);
    redc(pr_owc, pr_owc->tmp6,pr_owc->tmp6);
    invmodp(pr_owc, pr_owc->tmp6,pr_owc->modulus,pr_owc->tmp6);
    nres_modmult(pr_owc, w,pr_owc->tmp6,pr_owc->tmp5);
    nres_modmult(pr_owc, x,pr_owc->tmp6,z);
    copy(pr_owc->tmp5,y);
    return TRUE;
}

BOOL nres_multi_inverse(owcrypt *pr_owc, int m,OWC_BN *x,OWC_BN *w)
{
    int i;
    if (m==0) return TRUE;
    if (m<0) return FALSE;
    if (x==w)
    {
        return FALSE;
    }

    if (m==1)
    {
        copy(pr_owc->one,w[0]);
        nres_moddiv(pr_owc, w[0],x[0],w[0]);
        return TRUE;
    }

    convert(pr_owc, 1,w[0]);
    copy(x[0],w[1]);
    for (i=2;i<m;i++)
        nres_modmult(pr_owc, w[i-1],x[i-1],w[i]);

    nres_modmult(pr_owc, w[m-1],x[m-1],pr_owc->tmp6);
    if (size(pr_owc->tmp6)==0)
    {
        return FALSE;
    }

    redc(pr_owc, pr_owc->tmp6,pr_owc->tmp6);
    redc(pr_owc, pr_owc->tmp6,pr_owc->tmp6);

    invmodp(pr_owc, pr_owc->tmp6,pr_owc->modulus,pr_owc->tmp6);
    copy(x[m-1],pr_owc->tmp5);
    nres_modmult(pr_owc, w[m-1],pr_owc->tmp6,w[m-1]);

    for (i=m-2;;i--)
    {
        if (i==0)
        {
            nres_modmult(pr_owc, pr_owc->tmp5,pr_owc->tmp6,w[0]);
            break;
        }
        nres_modmult(pr_owc, w[i],pr_owc->tmp5,w[i]);
        nres_modmult(pr_owc, w[i],pr_owc->tmp6,w[i]);
        nres_modmult(pr_owc, pr_owc->tmp5,x[i],pr_owc->tmp5);
    }
    return TRUE;   
}

void ecurve_init(owcrypt *pr_owc, OWC_BN a,OWC_BN b,OWC_BN p)
{
    int as;
    prepare_monty(pr_owc, p);
    pr_owc->Asize=size(a);
    if (owc_abs(pr_owc->Asize)==OWC_TOOBIG)
    {
        if (pr_owc->Asize>=0)
        {
           copy(a,pr_owc->tmp1);
           divide(pr_owc, pr_owc->tmp1,p,p);
           subtract(pr_owc, p,pr_owc->tmp1,pr_owc->tmp1);
           as=size(pr_owc->tmp1);
           if (as<OWC_TOOBIG) pr_owc->Asize=-as;
        }
    }
    nres(pr_owc, a,pr_owc->A);

    pr_owc->Bsize=size(b);
    if (owc_abs(pr_owc->Bsize)==OWC_TOOBIG)
    {
        if (pr_owc->Bsize>=0)
        {
           copy(b,pr_owc->tmp1);
           divide(pr_owc, pr_owc->tmp1,p,p);
           subtract(pr_owc, p,pr_owc->tmp1,pr_owc->tmp1);
           as=size(pr_owc->tmp1);
           if (as<OWC_TOOBIG)
               pr_owc->Bsize=-as;
        }
    }
    nres(pr_owc, b,pr_owc->B);
    return;
}
