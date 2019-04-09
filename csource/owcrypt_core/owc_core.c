


#include "owcrypt_core.h"
#include <stdlib.h>
#include <string.h>

#define owcrypt_size(n) (((sizeof(struct bignum)+((n)+2)*sizeof(owc_unit))-1)/sizeof(long)+1)*sizeof(long)
#define owc_bn_reserve(n,m) ((n)*owcrypt_size(m)+sizeof(long))
#define owcrypt_pointsize(n) (((sizeof(owc_point)+owc_bn_reserve(2,(n)))-1)/sizeof(long)+1)*sizeof(long)
#define owc_point_reserve(n,m) ((n)*owcrypt_pointsize(m)+sizeof(long))

//owcrypt owc;
//owcrypt *pr_owc=&owc;

//owcrypt *get_owc()
//{
//  return (owcrypt *)pr_owc;
//}

owc_small muldiv(owc_small a,owc_small b,owc_small c,owc_small m,owc_small *rp)
{
    owc_small q;
    owc_large p=(owc_large)a*b+c;
    q=(owc_small)((p/m));
    *rp=(owc_small)(p-(owc_large)q*m);
    return q;
}

owc_small muldvm(owc_small a,owc_small c,owc_small m,owc_small *rp)
{
    owc_small q;
    union doubleword dble;
    dble.h[OWC_BOTTOM]=c;
    dble.h[OWC_TOP]=a;

    q=(owc_small)(dble.d/m);
    *rp=(owc_small)(dble.d-(owc_large)q*m);
    return q;
}

owc_small owc_shiftbits(owc_small x,int n)
{
    if (n==0)
        return x;
    if (n>0)
        x<<=n;
    else
        x>>=(-n);
    return x;
}

owc_small owc_setbase(owcrypt *pr_owc, owc_small nb)
{
    owc_small temp;
    BOOL fits;
    int bits;

    fits=FALSE;
    bits=OWCRYPT;
    while (bits>1) 
    {
        bits/=2;
        temp=((owc_small)1<<bits);
        if (temp==nb)
        {
            fits=TRUE;
            break;
        }
        if (temp<nb || (bits%2)!=0)
            break;
    }
    if (fits)
    {
        pr_owc->apbase=nb;
        pr_owc->pack=OWCRYPT/bits;
        pr_owc->base=0;
        return 0;
    }
    pr_owc->apbase=nb;
    pr_owc->pack=1;
    pr_owc->base=nb;

    if (pr_owc->base==0)
        return 0;
    temp=BASE_LIMMIT/nb;
    while (temp>=nb)
    {
        temp=temp/nb;
        pr_owc->base*=nb;
        pr_owc->pack++;
    }
    return 0;
}

void zero(OWC_BN x)
{
    int i,n;
    owc_small *g;
    if (x==NULL)
        return;
    n=(x->len&OWC_OB);
    g=x->w;
    for (i=0;i<n;i++)
        g[i]=0;
    x->len=0;
}

void uconvert(owcrypt *pr_owc,unsigned int n ,OWC_BN x)
{
    int m;

    zero(x);
    if (n==0)
        return;
    m=0;
    if (pr_owc->base==0)
    {
        x->w[m++]=(owc_small)n;
    }
    else
        while (n>0)
        {
            x->w[m++]=((owc_small)n%pr_owc->base);
            n=(unsigned int)((owc_small)n/pr_owc->base);
        }
    x->len=m;
}

void convert(owcrypt *pr_owc, int n ,OWC_BN x)
{
    unsigned int s;
    if (n==0)
    {
        zero(x);
        return;
        
    }
    s=0;
    if (n<0)
    {
        s=OWC_MSB;
        n=(-n);
    }
    uconvert( pr_owc,(unsigned int)n,x);
    x->len|=s;
}

OWC_BN bignum_init(owcrypt *pr_owc)
{
    OWC_BN x;
    int align;
    char *ptr;

    if (!(pr_owc->active))
    {
        return NULL;
    }

    x=(OWC_BN)owc_alloc(pr_owc, owcrypt_size(pr_owc->nib-1),1);
    if (x==NULL)
    {
        return x;
    }
    
    ptr=(char *)&x->w;
    align=(unsigned long)(ptr+sizeof(owc_small *))%sizeof(owc_small);
    x->w=(owc_small *)(ptr+sizeof(owc_small *)+sizeof(owc_small)-align);
    return x;
}

OWC_BN owcvar_mem_variable(char *mem,int index,int sz)
{
    OWC_BN x;
    int align;
    char *ptr;
    int offset,r;

    offset=0;
    r=(unsigned long)mem%sizeof(long);
    if (r>0)
        offset=sizeof(long)-r;

    x=(OWC_BN)&mem[offset+owcrypt_size(sz)*index];
    ptr=(char *)&x->w;
    align=(unsigned long)(ptr+sizeof(owc_small *))%sizeof(owc_small);   
    x->w=(owc_small *)(ptr+sizeof(owc_small *)+sizeof(owc_small)-align);   

    return x;
}

OWC_BN owcvar_mem(owcrypt *pr_owc, char *mem,int index)
{
    return owcvar_mem_variable(mem,index,pr_owc->nib-1);

}

owcrypt *owcsys_init(owcrypt *pr_owc)
{
    return owcsys_basic(pr_owc,256,2);
}

owcrypt *owcsys_basic(owcrypt *pr_owc,int nd,owc_small nb)
{
    owc_small b,nw;

    if (pr_owc==NULL)
        return NULL;
    if (sizeof(owc_double_unit)<2*sizeof(owc_unit))
    {
        return pr_owc;
    }
    if (nb==1 || nb>BASE_LIMMIT)
    {
        return pr_owc;
    }
    owc_setbase(pr_owc, nb);
    b=pr_owc->base;
    pr_owc->lg2b=0;
    pr_owc->base2=1;

    if (b==0)
    {
        pr_owc->lg2b=OWCRYPT;
        pr_owc->base2=0;
    }
    else while (b>1)
    {
        b=b/2;
        pr_owc->lg2b++;
        pr_owc->base2*=2;
    }
    if (nd>0)
        nw=((nd)-1)/(pr_owc->pack)+1;
    else
        nw=((8*(-nd))-1)/(pr_owc->lg2b)+1;
    if (nw<1) nw=1;
    pr_owc->nib=(int)(nw+1);
    pr_owc->check=ON;
    pr_owc->MONTY=ON;
    pr_owc->qnr=0;
    pr_owc->cnr=0;
    pr_owc->pmod8=0;
	pr_owc->pmod9=0;
    pr_owc->nib=2*pr_owc->nib+1;
    if (pr_owc->nib!=(int)(pr_owc->nib&(OWC_OB)))
    {
        pr_owc->nib=(pr_owc->nib-1)/2;
        return pr_owc;
    }
    pr_owc->tmp_alloc=(char *)memalloc(pr_owc, 26);
    pr_owc->active=ON;
    pr_owc->nib=(pr_owc->nib-1)/2;
    pr_owc->tmp0=owcvar_mem(pr_owc, pr_owc->tmp_alloc,0);
    pr_owc->tmp1=owcvar_mem(pr_owc, pr_owc->tmp_alloc,2);
    pr_owc->tmp2=owcvar_mem(pr_owc, pr_owc->tmp_alloc,3);
    pr_owc->tmp3=owcvar_mem(pr_owc, pr_owc->tmp_alloc,4);
    pr_owc->tmp4=owcvar_mem(pr_owc, pr_owc->tmp_alloc,5);
    pr_owc->tmp5=owcvar_mem(pr_owc, pr_owc->tmp_alloc,6);
    pr_owc->tmp6=owcvar_mem(pr_owc, pr_owc->tmp_alloc,8);
    pr_owc->tmp7=owcvar_mem(pr_owc, pr_owc->tmp_alloc,10);
    pr_owc->tmp8=owcvar_mem(pr_owc, pr_owc->tmp_alloc,12);
    pr_owc->tmp9=owcvar_mem(pr_owc, pr_owc->tmp_alloc,13);
    pr_owc->tmp10=owcvar_mem(pr_owc, pr_owc->tmp_alloc,14);
    pr_owc->tmp11=owcvar_mem(pr_owc, pr_owc->tmp_alloc,15);
    pr_owc->tmp12=owcvar_mem(pr_owc, pr_owc->tmp_alloc,16);
    pr_owc->tmp13=owcvar_mem(pr_owc, pr_owc->tmp_alloc,17);
    pr_owc->tmp14=owcvar_mem(pr_owc, pr_owc->tmp_alloc,18);
    pr_owc->tmp15=owcvar_mem(pr_owc, pr_owc->tmp_alloc,19);
    pr_owc->modulus=owcvar_mem(pr_owc, pr_owc->tmp_alloc,20);
    pr_owc->pR=owcvar_mem(pr_owc, pr_owc->tmp_alloc,21);
    pr_owc->A=owcvar_mem(pr_owc, pr_owc->tmp_alloc,23);
    pr_owc->B=owcvar_mem(pr_owc, pr_owc->tmp_alloc,24);
    pr_owc->one=owcvar_mem(pr_owc, pr_owc->tmp_alloc,25);

    return pr_owc;
}

void *memalloc(owcrypt *pr_owc, int num)
{
    return owc_alloc(pr_owc, owc_bn_reserve(num,pr_owc->nib-1),1);
}

void memkill(owcrypt *pr_owc,  char *mem,int len)
{
    if (mem==NULL)
        return;
    memset(mem,0,owc_bn_reserve(len,pr_owc->nib-1));
    owc_free(mem);
}

void bignum_clear(OWC_BN x)
{
    if (x==NULL) return;
    zero(x);
    owc_free(x);
}

int exsign(OWC_BN x)
{
    if ((x->len&(OWC_MSB))==0)
        return PLUS;
    else
        return MINUS;
}

void insign(int s,OWC_BN x)
{
    if (x->len==0)
        return;
    if (s<0)
        x->len|=OWC_MSB;
    else
        x->len&=OWC_OB;
}   

void owc_lzero(OWC_BN x)
{
    unsigned int s;
    int m;
    s=(x->len&(OWC_MSB));
    m=(int)(x->len&(OWC_OB));
    while (m>0 && x->w[m-1]==0)
        m--;
    x->len=m;
    if (m>0)
        x->len|=s;
}

int getdig(owcrypt *pr_owc,  OWC_BN x,int i)
{
    int k;
    owc_small n;
    i--;
    n=x->w[i/pr_owc->pack];
    if (pr_owc->pack==1)
        return (int)n;
    k=i%pr_owc->pack;
    for (i=1;i<=k;i++)
        n=n/pr_owc->apbase;
    return (int)(n%pr_owc->apbase);
}

void copy(OWC_BN x,OWC_BN y)
{
    int i,nx,ny;
    owc_small *gx,*gy;
    if (x==y || y==NULL)
        return;

    if (x==NULL)
    { 
        zero(y);
        return;
    }

    ny=(y->len&(OWC_OB));
    nx=(x->len&(OWC_OB));
    gx=x->w;
    gy=y->w;

    for (i=nx;i<ny;i++)
        gy[i]=0;
    for (i=0;i<nx;i++)
        gy[i]=gx[i];
    y->len=x->len;

}

void negify(OWC_BN x,OWC_BN y)
{
    copy(x,y);
    if (y->len!=0)
        y->len^=OWC_MSB;
}

void owc_shift(owcrypt *pr_owc,  OWC_BN x,int n,OWC_BN w)
{
    unsigned int s;
    int i,bl;
    owc_small *gw=w->w;

    copy(x,w);
    if (w->len==0 || n==0)
        return;
    s=(w->len&(OWC_MSB));
    bl=(int)(w->len&(OWC_OB))+n;
    if (bl<=0)
    {
        zero(w);
        return;
    }
    if (bl>pr_owc->nib && pr_owc->check) return;
    if (n>0)
    {
        for (i=bl-1;i>=n;i--)
            gw[i]=gw[i-n];
        for (i=0;i<n;i++)
            gw[i]=0;
    }
    else
    {
        n=(-n);
        for (i=0;i<bl;i++)
            gw[i]=gw[i+n];
        for (i=0;i<n;i++)
            gw[bl+i]=0;
    }
    w->len=(bl|s);
}

int size(OWC_BN x)
{
    int n,m;
    unsigned int s;
    if (x==NULL) return 0;
    s=(x->len&OWC_MSB);
    m=(int)(x->len&OWC_OB);
    if (m==0)
        return 0;
    if (m==1 && x->w[0]<(owc_small)OWC_TOOBIG)
        n=(int)x->w[0];
    else
        n=OWC_TOOBIG;
    if (s==OWC_MSB)
        return (-n);
    return n;
}

int owc_compare(OWC_BN x,OWC_BN y)
{
    int m,n,sig;
    unsigned int sx,sy;
    if (x==y)
        return 0;
    sx=(x->len&OWC_MSB);
    sy=(y->len&OWC_MSB);
    if (sx==0)
        sig=PLUS;
    else
        sig=MINUS;
    if (sx!=sy)
        return sig;
    m=(int)(x->len&OWC_OB);
    n=(int)(y->len&OWC_OB);
    if (m>n)
        return sig;
    if (m<n)
        return -sig;
    while (m>0)
    {
        m--;  
        if (x->w[m]>y->w[m])
            return sig;
        if (x->w[m]<y->w[m])
            return -sig;
    }
    return 0;
}

int owc_testbit(owcrypt *pr_owc,  OWC_BN x,int n)
{
    if ((x->w[n/pr_owc->lg2b] & ((owc_small)1<<(n%pr_owc->lg2b))) >0)
        return 1;
    return 0;
}



int owc_naf_window(owcrypt *pr_owc,  OWC_BN x,OWC_BN x3,int i,int *nbs,int *nzs,int store)
{
    int nb,j,r,biggest;

    nb=owc_testbit(pr_owc, x3,i)-owc_testbit(pr_owc, x,i);

    *nbs=1;
    *nzs=0;
    if (nb==0)
        return 0;
    if (i==0)
        return nb;

    biggest=2*store-1;
    if (nb>0)
        r=1;
    else
        r=(-1);

    for (j=i-1;j>0;j--)
    {
        (*nbs)++;
        r*=2;
        nb=owc_testbit(pr_owc, x3,j)-owc_testbit(pr_owc, x,j);
        if (nb>0)
            r+=1;
        if (nb<0)
            r-=1;
        if (abs(r)>biggest)
            break;
    }

    if (r%2!=0 && j!=0)
    {
        if (nb>0)
            r=(r-1)/2;
        if (nb<0)
            r=(r+1)/2;
        (*nbs)--;
    }
    
    while (r%2==0)
    {
        r/=2;
        (*nzs)++;
        (*nbs)--;
    }     
    return r;
}

BOOL point_at_infinity(owc_point *p)
{
    if (p==NULL)
        return FALSE;
    if (p->marker==OWC_POINT_INFINITY)
        return TRUE;
    return FALSE;
}

owc_point* epoint_init(owcrypt *pr_owc )
{
    owc_point *p;
    char *ptr;
    p=(owc_point *)owc_alloc(pr_owc, owcrypt_pointsize(pr_owc->nib-1),1);
    ptr=(char *)p+sizeof(owc_point);
    p->X=owcvar_mem(pr_owc, ptr,0);
    p->Y=owcvar_mem(pr_owc, ptr,1);
    p->marker=OWC_POINT_INFINITY;
    return p;
}


owc_point* epoint_init_mem_variable( char *mem,int index,int sz)
{
    owc_point *p;
    char *ptr;
    int offset,r;
    offset=0;
    r=(unsigned long)mem%sizeof(long);
    if (r>0)
        offset=sizeof(long)-r;
    p=(owc_point *)&mem[offset+index*owcrypt_pointsize(sz)];
    ptr=(char *)p+sizeof(owc_point);
    p->X=owcvar_mem_variable(ptr,0,sz);
    p->Y=owcvar_mem_variable(ptr,1,sz);
    p->marker=OWC_POINT_INFINITY;
    return p;
}

owc_point* epoint_init_mem(owcrypt *pr_owc,  char *mem,int index)
{
    return epoint_init_mem_variable( mem,index,pr_owc->nib-1);
}

void *ecp_memalloc(owcrypt *pr_owc, int num)
{
    return owc_alloc(pr_owc,  owc_point_reserve(num,pr_owc->nib-1),1);
}

void ecp_memkill(owcrypt *pr_owc,  char *mem,int num)
{
    if (mem==NULL)
        return;
    memset(mem,0,owc_point_reserve(num,pr_owc->nib-1));
    owc_free(mem);

}

void epoint_free(owc_point *p)
{
    if (p==NULL)
        return;
    zero(p->X);
    zero(p->Y);

    owc_free(p);
}        

owc_small sgcd(owc_small x,owc_small y)
{
    owc_small r;
    if (y==(owc_small)0)
        return x;
    while ((r=(x%y))!=(owc_small)0)
    {
        x=y;
        y=r;
    }
    return y;
}
