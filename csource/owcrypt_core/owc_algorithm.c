
#include "owcrypt_core.h"

//z = x + y
//x and y are both positive
void owc_padd(owcrypt *pr_owc,  OWC_BN x,OWC_BN y,OWC_BN z)
{
    int i,lx,ly,lz,la;
    owc_small carry,psum;
    owc_small *gx,*gy,*gz;
    lx = (int)x->len;
    ly = (int)y->len;
    
    if (ly>lx)
    {
        lz=ly;
        la=lx;
        if (x!=z)
            copy(y,z);
        else
            la=ly;
    }
    else
    {
        lz=lx;
        la=ly;
        if (y!=z)
            copy(x,z);
        else
            la=lx;
    }
    carry=0;
    z->len=lz;
    gx=x->w;
    gy=y->w;
    gz=z->w;
    if (lz<pr_owc->nib || !pr_owc->check)
        z->len++;
    if (pr_owc->base==0) 
    {
        for (i=0;i<la;i++)
        {
            psum=gx[i]+gy[i]+carry;
            if (psum>gx[i])
                carry=0;
            else if (psum<gx[i])
                carry=1;
            gz[i]=psum;
        }
        for (;i<lz && carry>0;i++ )
        {
            psum=gx[i]+gy[i]+carry;
            if (psum>gx[i])
                carry=0;
            else if (psum<gx[i])
                carry=1;
            gz[i]=psum;
        }
        if (carry)
        {
            if (pr_owc->check && i>=pr_owc->nib)
            {
                return;
            }
            gz[i]=carry;
        }
    }
    else
    {
        for (i=0;i<la;i++)
        {
            psum=gx[i]+gy[i]+carry;
            carry=0;
            if (psum>=pr_owc->base)
            {
                carry=1;
                psum-=pr_owc->base;
            }
            gz[i]=psum;
        }
        for (;i<lz && carry>0;i++)
        {
            psum=gx[i]+gy[i]+carry;
            carry=0;
            if (psum>=pr_owc->base)
            {
                carry=1;
                psum-=pr_owc->base;
            }
            gz[i]=psum;
        }
        if (carry)
        {
            if (pr_owc->check && i>=pr_owc->nib)
            {
                return;
            }
            gz[i]=carry;
        }
    }
    if (gz[z->len-1]==0)
        z->len--;

}
// z = x - y
// x and y are both positive
// x > y
void owc_psub(owcrypt *pr_owc,  OWC_BN x,OWC_BN y,OWC_BN z)
{
    int i,lx,ly;
    owc_small borrow,pdiff;
    owc_small *gx,*gy,*gz;
    lx = (int)x->len;
    ly = (int)y->len;
    if (ly>lx)
    {
        return;
    }
    if (y!=z)
        copy(x,z);
    else
        ly=lx;
    z->len=lx;
    gx=x->w;
    gy=y->w;
    gz=z->w;
    borrow=0;
    if (pr_owc->base==0)
    {
        for (i=0;i<ly || borrow>0;i++)
        {
            if (i>lx)
            {
                return;
            }
            pdiff=gx[i]-gy[i]-borrow;
            if (pdiff<gx[i])
                borrow=0;
            else if (pdiff>gx[i])
                borrow=1;
            gz[i]=pdiff;
        }
    }
    else for (i=0;i<ly || borrow>0;i++)
    {
        if (i>lx)
        {
            return;
        }
        pdiff=gy[i]+borrow;
        borrow=0;
        if (gx[i]>=pdiff)
            pdiff=gx[i]-pdiff;
        else
        {
            pdiff=pr_owc->base+gx[i]-pdiff;
            borrow=1;
        }
        gz[i]=pdiff;
    }
    owc_lzero(z);
}

static void owc_select(owcrypt *pr_owc,  OWC_BN x,int d,OWC_BN y,OWC_BN z)
{
    int sx,sy,sz,jf,xgty;
    sx=exsign(x);
    sy=exsign(y);
    sz=0;
    x->len&=OWC_OB;
    y->len&=OWC_OB;
    xgty=owc_compare(x,y);
    jf=(1+sx)+(1+d*sy)/2;
    switch (jf)
    {
    case 0:
        if (xgty>=0)
            owc_padd(pr_owc, x,y,z);
        else
            owc_padd(pr_owc, y,x,z);
        sz=MINUS;
        break;
    case 1:
        if (xgty<=0)
        {
            owc_psub(pr_owc, y,x,z);
            sz=PLUS;
        }
        else
        {
            owc_psub(pr_owc, x,y,z);
            sz=MINUS;
        }
        break;
    case 2:
        if (xgty>=0)
        {
            owc_psub(pr_owc, x,y,z);
            sz=PLUS;
        }
        else
        {
            owc_psub(pr_owc, y,x,z);
            sz=MINUS;
        }
        break;
    case 3:
        if (xgty>=0)
            owc_padd(pr_owc, x,y,z);
        else
            owc_padd(pr_owc, y,x,z);
        sz=PLUS;
        break;
    }
    if (sz<0)
        z->len^=OWC_MSB;
    if (x!=z && sx<0)
        x->len^=OWC_MSB;
    if (y!=z && y!=x && sy<0)
        y->len^=OWC_MSB;
}

void add(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN z)
{
    owc_select(pr_owc, x,PLUS,y,z);
}

void subtract(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN z)
{
    owc_select(pr_owc, x,MINUS,y,z);
}

void incr(owcrypt *pr_owc ,OWC_BN x,int n,OWC_BN z)
{
    convert(pr_owc , n,pr_owc->tmp0);
    owc_select(pr_owc , x,PLUS,pr_owc->tmp0,z);
}

void decr(owcrypt *pr_owc, OWC_BN x,int n,OWC_BN z)
{
    convert(pr_owc , n,pr_owc->tmp0);
    owc_select(pr_owc , x,MINUS,pr_owc->tmp0,z);
}

void owc_pmul(owcrypt *pr_owc,  OWC_BN x,owc_small sn,OWC_BN z)
{
    int m,xl;
    unsigned int sx;
    owc_small carry,*xg,*zg;
    union doubleword dble;
    owc_large dbled;
    if (x!=z)
    {
        zero(z);
        if (sn==0)
            return;
    }
    else if (sn==0)
    {
        zero(z);
        return;
    }
    m=0;
    carry=0;
    sx=x->len&OWC_MSB;
    xl=(int)(x->len&OWC_OB);
    
    if (pr_owc->base==0)
    {
        xg=x->w;
        zg=z->w;

        for (m=0;m<xl;m++)
        {
            dble.d=(owc_large)x->w[m]*sn+carry;
            carry=dble.h[OWC_TOP];
            z->w[m]=dble.h[OWC_BOTTOM];
        }
        
        if (carry>0)
        {
            m=xl;
            if (m>=pr_owc->nib && pr_owc->check)
            {
                return;
            }
            z->w[m]=carry;
            z->len=m+1;
        }
        else z->len=xl;
    }
    else while (m<xl || carry>0)
    {
        if (m>pr_owc->nib && pr_owc->check)
        {
            return;
        }
        
        dbled=(owc_large)x->w[m]*sn+carry;
        if (pr_owc->base==pr_owc->base2)
            carry=(owc_small)(dbled>>pr_owc->lg2b);
        else
            carry=(owc_small)(dbled/pr_owc->base);
        z->w[m]=(owc_small)(dbled-(owc_large)carry*pr_owc->base);
        
        m++;
        z->len=m;
    }
    
    if (z->len!=0)
        z->len|=sx;
}

void premult(owcrypt *pr_owc,  OWC_BN x,int n,OWC_BN z)
{
    if (n==0)
    {
        zero(z);
        return;
    }
    if (n==1)
    {
        copy(x,z);
        return;
    }
    if (n<0)
    {
        n=(-n);
        owc_pmul(pr_owc,x,(owc_small)n,z);
        if (z->len!=0)
            z->len^=OWC_MSB;
    }
    else
        owc_pmul(pr_owc, x,(owc_small)n,z);
}

owc_small owc_sdiv( owcrypt *pr_owc,OWC_BN x,owc_small sn,OWC_BN z)
{
    int i,xl;
    owc_small sr,*xg,*zg;
    
    union doubleword dble;
    owc_large dbled;
    
    sr=0;
    xl=(int)(x->len&OWC_OB);
    if (x!=z)
        zero(z);
    if (pr_owc->base==0)
    {
        xg=x->w;
        zg=z->w;

        for (i=xl-1;i>=0;i--)
        {
            dble.h[OWC_BOTTOM]=x->w[i];
            dble.h[OWC_TOP]=sr;
            z->w[i]=(owc_small)(dble.d/sn);
            sr=(owc_small)(dble.d-(owc_large)z->w[i]*sn);
        }
    }
    else
        for (i=xl-1;i>=0;i--)
        {
            dbled=(owc_large)sr*pr_owc->base+x->w[i];
            z->w[i]=(owc_small)(dbled/sn);
            sr=(owc_small)(dbled-(owc_large)z->w[i]*sn);
        }
    z->len=x->len;
    owc_lzero(z);
    return sr;
}

int subdiv(owcrypt *pr_owc, OWC_BN x,int n,OWC_BN z)
{
    unsigned int sx;
    int r,i,msb;
    owc_small lsb;
    
    if (n==0)
        return 0;
    
    if (x->len==0)
    {
        zero(z);
        return 0;
    }
    if (n==1)
    {
        copy(x,z);
        return 0;
    }
    sx=(x->len&OWC_MSB);
    if (n==2 && pr_owc->base==0)
    {
        copy(x,z);
        msb=(int)(z->len&OWC_OB)-1;
        r=(int)z->w[0]&1;
        for (i=0;;i++)
        {
            z->w[i]>>=1;
            if (i==msb)
            {
                if (z->w[i]==0)
                    owc_lzero(z);
                break;
            }
            lsb=z->w[i+1]&1;
            z->w[i]|=(lsb<<(OWCRYPT-1));
        }
        
        if (sx==0)
            return r;
        else
            return (-r);
    }
    
    if (n<0)
    {
        n=(-n);
        r=(int)owc_sdiv(pr_owc, x,(owc_small)n,z);
        if (z->len!=0)
            z->len^=OWC_MSB;
    }
    else r=(int)owc_sdiv(pr_owc, x,(owc_small)n,z);
    if (sx==0)
        return r;
    else
        return (-r);
}

int remain(owcrypt *pr_owc, OWC_BN x,int n)
{
    int r;
    unsigned int sx;

    sx=(x->len&OWC_MSB);
    
    if (n==2 && pr_owc->base%2==0)
    {
        if ((int)(x->w[0]%2)==0)
            return 0;
        else
        {
            if (sx==0)
                return 1;
            else
                return (-1);
        }
    }
    if (n==8 && (pr_owc->base%8)==0)
    {
        r=(int)(x->w[0]%8);
        if (sx!=0)
            r=-r;
        return r;
    }
    
    copy(x,pr_owc->tmp0);
    r=subdiv(pr_owc, pr_owc->tmp0,n,pr_owc->tmp0);
    return r;
}

BOOL subdivisible(owcrypt *pr_owc, OWC_BN x,int n)
{
    if (remain(pr_owc, x,n)==0)
        return TRUE;
    else
        return FALSE;
}

void absol(OWC_BN x,OWC_BN y)
{
    copy(x,y);
    y->len&=OWC_OB;
}

void bytes_to_big(owcrypt *pr_owc, int len,const char *ptr,OWC_BN x)
{
    int i,j,m,n,r;
    unsigned int dig;
    unsigned char ch;
    owc_small wrd;
    zero(x);
    
    if (len<=0)
    {
        return;
    }

    while (*ptr==0)
    {
        ptr++; len--;
        if (len==0)
        {
            return;
        }
    }
    
    if (pr_owc->base==0)
    {
        m=OWCRYPT/8;
        n=len/m;
        
        r=len%m;
        wrd=(owc_small)0;
        if (r!=0)
        {
            n++;
            for (j=0;j<r;j++)
            {
                wrd<<=8;
                wrd|=OWC_TOBYTE(*ptr++);
            }
        }
        x->len=n;
        if (n>pr_owc->nib && pr_owc->check)
        {
            return;
        }
        if (r!=0)
        {
            n--;
            x->w[n]=wrd;
        }
        
        for (i=n-1;i>=0;i--)
        {
            for (j=0;j<m;j++)
            {
                wrd<<=8;
                wrd|=OWC_TOBYTE(*ptr++);
            }
            x->w[i]=wrd;
        }
        owc_lzero(x); 
    }
    else
    {
        for (i=0;i<len;i++)
        {
            premult(pr_owc, x,256,x);
            ch=OWC_TOBYTE(ptr[i]);
            dig=ch;
            incr(pr_owc, x,(int)dig,x);
        }
    }
}

int big_to_bytes(owcrypt *pr_owc, int max,OWC_BN x,char *ptr,BOOL justify)
{
    int i,j,r,m,n,len,start;
    unsigned int dig;
    unsigned char ch;
    owc_small wrd;
    
    if ( max<0) return 0;
    
    if (max==0 && justify)
        return 0;
    if (size(x)==0)
    {
        if (justify)
        {
            for (i=0;i<max;i++)
                ptr[i]=0;
            return max;
        }
        return 0;
    }
    
    owc_lzero(x);
    if (pr_owc->base==0)
    {
        m=OWCRYPT/8;
        n=(int)(x->len&OWC_OB);
        n--;
        len=n*m;
        wrd=x->w[n];
        r=0;
        while (wrd!=(owc_small)0)
        {
            r++;
            wrd>>=8;
            len++;
            
        }
        r%=m;
        
        if (max>0 && len>max)
        {
            return 0;
        }
        
        if (justify)
        {
            start=max-len;
            for (i=0;i<start;i++)
                ptr[i]=0;
        }
        else start=0;
        
        if (r!=0)
        {
            wrd=x->w[n--];
            for (i=r-1;i>=0;i--)
            {
                ptr[start+i]=(char)(wrd&0xFF);
                wrd>>=8;
            }
        }
        
        for (i=r;i<len;i+=m)
        {
            wrd=x->w[n--];
            for (j=m-1;j>=0;j--)
            {
                ptr[start+i+j]=(char)(wrd&0xFF);
                wrd>>=8;
            }
        }
    }
    else
    {
        copy(x,pr_owc->tmp1);
        for (len=0;;len++)
        {
            if (size(pr_owc->tmp1)==0)
            {
                if (justify)
                {
                    if (len==max)
                        break;
                }
                else
                    break;
            }
            
            if (max>0 && len>=max)
            {
                return 0;
            }
            
            dig=(unsigned int)subdiv(pr_owc, pr_owc->tmp1,256,pr_owc->tmp1);
            ch=OWC_TOBYTE(dig);
            for (i=len;i>0;i--)
                ptr[i]=ptr[i-1];
            ptr[0]=OWC_TOBYTE(ch);
        }
    }
    if (justify)
        return max;
    else
        return len;
}


owc_small normalise(owcrypt *pr_owc, OWC_BN x,OWC_BN y)
{
    owc_small norm,r;
    int len;

    if (x!=y) copy(x,y);
    len=(int)(y->len&OWC_OB);
    if (pr_owc->base==0)
    {
        if ((r=y->w[len-1]+1)==0)
            norm=1;
        else
            norm=(owc_small)(((owc_large)1 << OWCRYPT)/r);
        if (norm!=1)
            owc_pmul(pr_owc, y,norm,y);
    }
    else
    {
        norm=pr_owc->base/(owc_small)(y->w[len-1]+1);
        if (norm!=1)
            owc_pmul(pr_owc, y,norm,y);
    }
    return norm;
}

void multiply(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN z)
{
    int i,xl,yl,j,ti;
    owc_small carry,*xg,*yg,*w0g;
    
    unsigned int sz;
    OWC_BN w0;
    union doubleword dble;
    owc_large dbled;
    if (y->len==0 || x->len==0)
    {
        zero(z);
        return;
    }
    if (x!=pr_owc->tmp5 && y!=pr_owc->tmp5 && z==pr_owc->tmp5)
        w0=pr_owc->tmp5;
    else
        w0=pr_owc->tmp0;
    
    sz=((x->len&OWC_MSB)^(y->len&OWC_MSB));
    xl=(int)(x->len&OWC_OB);
    yl=(int)(y->len&OWC_OB);
    zero(w0);
    if (pr_owc->check && xl+yl>pr_owc->nib)
    {
        return;
    }
    if (pr_owc->base==0)
    {
        xg=x->w;
        yg=y->w;
        w0g=w0->w;
        if (x==y && xl>5)
        {
            for (i=0;i<xl-1;i++)
            {
                carry=0;
                for (j=i+1;j<xl;j++)
                {
                    dble.d=(owc_large)x->w[i]*x->w[j]+carry+w0->w[i+j];
                    w0->w[i+j]=dble.h[OWC_BOTTOM];
                    carry=dble.h[OWC_TOP];
                }
                w0->w[xl+i]=carry;
            }
            
            w0->len=xl+xl-1;
            owc_padd(pr_owc, w0,w0,w0);
            carry=0;
            for (i=0;i<xl;i++)
            {
                ti=i+i;
                dble.d=(owc_large)x->w[i]*x->w[i]+carry+w0->w[ti];
                w0->w[ti]=dble.h[OWC_BOTTOM];
                carry=dble.h[OWC_TOP];
                w0->w[ti+1]+=carry;
                if (w0->w[ti+1]<carry)
                    carry=1;
                else
                    carry=0;
            }
        }
        else for (i=0;i<xl;i++)
        {
            carry=0;
            for (j=0;j<yl;j++)
            {
                dble.d=(owc_large)x->w[i]*y->w[j]+carry+w0->w[i+j];
                w0->w[i+j]=dble.h[OWC_BOTTOM];
                carry=dble.h[OWC_TOP];
            }
            w0->w[yl+i]=carry;
        }
    }
    else
    {
        if (x==y && xl>5)
        {
            for (i=0;i<xl-1;i++)
            {
                carry=0;
                for (j=i+1;j<xl;j++)
                {
                    dbled=(owc_large)x->w[i]*x->w[j]+w0->w[i+j]+carry;
                    if (pr_owc->base==pr_owc->base2)
                        carry=(owc_small)(dbled>>pr_owc->lg2b);
                    else
                        carry=(owc_small)(dbled/pr_owc->base);
                    w0->w[i+j]=(owc_small)(dbled-(owc_large)carry*pr_owc->base);
                }
                w0->w[xl+i]=carry;
            }
            w0->len=xl+xl-1;
            owc_padd(pr_owc, w0,w0,w0);
            carry=0;
            for (i=0;i<xl;i++)
            {
                ti=i+i;
                dbled=(owc_large)x->w[i]*x->w[i]+w0->w[ti]+carry;
                if (pr_owc->base==pr_owc->base2)
                    carry=(owc_small)(dbled>>pr_owc->lg2b);
                else
                    carry=(owc_small)(dbled/pr_owc->base);
                w0->w[ti]=(owc_small)(dbled-(owc_large)carry*pr_owc->base);
                w0->w[ti+1]+=carry;
                carry=0;
                if (w0->w[ti+1]>=pr_owc->base)
                {
                    carry=1;
                    w0->w[ti+1]-=pr_owc->base;
                }
            }
        }
        else for (i=0;i<xl;i++)
        {
            carry=0;
            for (j=0;j<yl;j++)
            {
                dbled=(owc_large)x->w[i]*y->w[j]+w0->w[i+j]+carry;
                if (pr_owc->base==pr_owc->base2)
                    carry=(owc_small)(dbled>>pr_owc->lg2b);
                else
                    carry=(owc_small)(dbled/pr_owc->base);
                w0->w[i+j]=(owc_small)(dbled-(owc_large)carry*pr_owc->base);
            }
            w0->w[yl+i]=carry;
        }
    }
    
    w0->len=(sz|(xl+yl));
    owc_lzero(w0);
    copy(w0,z);
}

void divide(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN z)
{
    owc_small carry,attemp,ldy,sdy,ra,r,d,tst,psum;
    unsigned int sx,sy,sz;
    owc_small borrow,dig,*w0g,*yg;
    int i,k,m,x0,y0,w00;
    OWC_BN w0;
    
    union doubleword dble;
    owc_large dbled;
    
    BOOL check;

    w0=pr_owc->tmp0;

    if (x==y)
        return;
    
    if (y->len==0)
        return;

    sx=(x->len&OWC_MSB);
    sy=(y->len&OWC_MSB);
    sz=(sx^sy);
    x->len&=OWC_OB;
    y->len&=OWC_OB;
    x0=(int)x->len;
    y0=(int)y->len;
    copy(x,w0);
    w00=(int)w0->len;
    if (pr_owc->check && (w00-y0+1>pr_owc->nib))
    {
        return;
    }
    d=0;
    if (x0==y0)
    {
        if (x0==1)
        {
            d=w0->w[0]/y->w[0];
            w0->w[0]=(w0->w[0]%y->w[0]);
            owc_lzero(w0);
        }
        else if ((w0->w[x0-1]/4) <y->w[x0-1])
            while (owc_compare(w0,y)>=0)
            {
                owc_psub(pr_owc, w0,y,w0);
                d++;
            }
    }
    if (owc_compare(w0,y)<0)
    {
        if (x!=z)
        {
            copy(w0,x);
            if (x->len!=0)
                x->len|=sx;
        }
        if (y!=z)
        {
            zero(z);
            z->w[0]=d;
            if (d>0)
                z->len=(sz|1);
        }
        y->len|=sy;
        return;
    }
    
    if (y0==1)
    {
        r=owc_sdiv(pr_owc, w0,y->w[0],w0);
        
        if (y!=z)
        {
            copy(w0,z);
            z->len|=sz;
        }
        if (x!=z)
        {
            zero(x);
            x->w[0]=r;
            if (r>0)
                x->len=(sx|1);
        }
        y->len|=sy;
        return;
    }
    if (y!=z)
        zero(z);
    d=normalise(pr_owc, y,y);
    check=pr_owc->check;
    pr_owc->check=OFF;
    if (pr_owc->base==0)
    {
        if (d!=1)
            owc_pmul(pr_owc, w0,d,w0);
        ldy=y->w[y0-1];
        sdy=y->w[y0-2];
        w0g=w0->w;
        yg=y->w;
        for (k=w00-1;k>=y0-1;k--)
        {
            carry=0;
            if (w0->w[k+1]==ldy)
            {
                attemp=(owc_small)(-1);
                ra=ldy+w0->w[k];
                if (ra<ldy)
                    carry=1;
            }
            else
            {
                dble.h[OWC_BOTTOM]=w0->w[k];
                dble.h[OWC_TOP]=w0->w[k+1];
                attemp=(owc_small)(dble.d/ldy);
                ra=(owc_small)(dble.d-(owc_large)attemp*ldy);
            }
            
            while (carry==0)
            {
                dble.d=(owc_large)attemp*sdy;
                r=dble.h[OWC_BOTTOM];
                tst=dble.h[OWC_TOP];
                if (tst< ra || (tst==ra && r<=w0->w[k-1]))
                    break;
                attemp--;
                ra+=ldy;
                if (ra<ldy)
                    carry=1;
            }
            m=k-y0+1;
            if (attemp>0)
            {
                borrow=0;
                for (i=0;i<y0;i++)
                {
                    dble.d=(owc_large)attemp*y->w[i]+borrow;
                    dig=dble.h[OWC_BOTTOM];
                    borrow=dble.h[OWC_TOP];
                    
                    if (w0->w[m+i]<dig)
                        borrow++;
                    w0->w[m+i]-=dig;
                }
                if (w0->w[k+1]<borrow)
                {
                    w0->w[k+1]=0;
                    carry=0;
                    for (i=0;i<y0;i++)
                    {
                        psum=w0->w[m+i]+y->w[i]+carry;
                        if (psum>y->w[i])
                            carry=0;
                        if (psum<y->w[i])
                            carry=1;
                        w0->w[m+i]=psum;
                    }
                    attemp--;
                }
                else w0->w[k+1]-=borrow;
            }
            if (k==w00-1 && attemp==0)
                w00--;
            else if (y!=z)
                z->w[m]=attemp;
        }
    }
    else
    {
        if (d!=1)
            owc_pmul(pr_owc, w0,d,w0);
        ldy=y->w[y0-1];
        sdy=y->w[y0-2];
        
        for (k=w00-1;k>=y0-1;k--)
        {
            if (w0->w[k+1]==ldy)
            {
                attemp=pr_owc->base-1;
                ra=ldy+w0->w[k];
            }
            else
            {
                dbled=(owc_large)w0->w[k+1]*pr_owc->base+w0->w[k];
                attemp=(owc_small)(dbled/ldy);
                ra=(owc_small)(dbled-(owc_large)attemp*ldy);
            }
            while (ra<pr_owc->base)
            {
                dbled=(owc_large)sdy*attemp;
                if (pr_owc->base==pr_owc->base2)
                    tst=(owc_small)(dbled>>pr_owc->lg2b);
                else
                    tst=(owc_small)(dbled/pr_owc->base);
                
                r=(owc_small)(dbled-(owc_large)tst*pr_owc->base);
                if (tst< ra || (tst==ra && r<=w0->w[k-1]))
                    break;
                attemp--;
                ra+=ldy;
            }
            m=k-y0+1;
            if (attemp>0)
            {
                borrow=0;
                for (i=0;i<y0;i++)
                {
                    dbled=(owc_large)attemp*y->w[i]+borrow;
                    
                    if (pr_owc->base==pr_owc->base2)
                        borrow=(owc_small)(dbled>>pr_owc->lg2b);
                    else
                        borrow=(owc_small)(dbled/pr_owc->base);
                    dig=(owc_small)(dbled-(owc_large)borrow*pr_owc->base);
                    if (w0->w[m+i]<dig)
                    {
                        borrow++;
                        w0->w[m+i]+=(pr_owc->base-dig);
                    }
                    else w0->w[m+i]-=dig;
                }
                if (w0->w[k+1]<borrow)
                {
                    w0->w[k+1]=0;
                    carry=0;
                    for (i=0;i<y0;i++)
                    {
                        psum=w0->w[m+i]+y->w[i]+carry;
                        carry=0;
                        if (psum>=pr_owc->base)
                        {
                            carry=1;
                            psum-=pr_owc->base;
                        }
                        w0->w[m+i]=psum;
                    }
                    attemp--;
                }
                else
                    w0->w[k+1]-=borrow;
            }
            if (k==w00-1 && attemp==0)
                w00--;
            else if (y!=z)
                z->w[m]=attemp;
        }
    }
    if (y!=z)
        z->len=((w00-y0+1)|sz);
    
    w0->len=y0;
    
    owc_lzero(y);
    owc_lzero(z);
    
    if (x!=z)
    {
        owc_lzero(w0);
        if (d!=1)
            owc_sdiv(pr_owc, w0,d,x);
        else
            copy(w0,x);
        if (x->len!=0)
            x->len|=sx;
    }
    if (d!=1)
        owc_sdiv(pr_owc, y,d,y);
    y->len|=sy;
    pr_owc->check=check;
}

BOOL divisible(owcrypt *pr_owc, OWC_BN x,OWC_BN y)
{
    copy (x,pr_owc->tmp0);
    divide(pr_owc, pr_owc->tmp0,y,y);

    if (size(pr_owc->tmp0)==0)
        return TRUE;
    else
        return FALSE;
}

void mad(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN z,OWC_BN w,OWC_BN q,OWC_BN r)
{
    BOOL check;
    if (w==r)
    {
        return;
    }
    check=pr_owc->check;
    pr_owc->check=OFF;
    
    multiply(pr_owc, x,y,pr_owc->tmp0);
    if (x!=z && y!=z) add(pr_owc, pr_owc->tmp0,z,pr_owc->tmp0);
    
    divide(pr_owc, pr_owc->tmp0,w,q);
    if (q!=r) copy(pr_owc->tmp0,r);
    pr_owc->check=check;
}



int logb2(owcrypt *pr_owc, OWC_BN x)
{
    int xl,lg2;
    owc_small top;
    if (size(x)==0)
        return 0;
    
    if (pr_owc->base==pr_owc->base2)
    {
        xl=(int)(x->len&OWC_OB);
        lg2=pr_owc->lg2b*(xl-1);
        top=x->w[xl-1];
        while (top>=1)
        {
            lg2++;
            top/=2;
        }
    }
    else
    {
        copy(x,pr_owc->tmp0);
        insign(PLUS,pr_owc->tmp0);
        lg2=0;
        while (pr_owc->tmp0->len>1)
        {
            owc_sdiv(pr_owc, pr_owc->tmp0,pr_owc->base2,pr_owc->tmp0);
            lg2+=pr_owc->lg2b;
        }
        
        while (pr_owc->tmp0->w[0]>=1)
        {
            lg2++;
            pr_owc->tmp0->w[0]/=2;
        }
    }
    return lg2;
}

void expb2(owcrypt *pr_owc, int n,OWC_BN x)
{
    int r,p;
    int i;

    convert(pr_owc, 1,x);
    if (n==0)
        return;

    if (n<0)
    {
        return;
    }
    r=n/pr_owc->lg2b;
    p=n%pr_owc->lg2b;
    
    if (pr_owc->base==pr_owc->base2)
    {
        owc_shift(pr_owc, x,r,x);
        x->w[x->len-1]=owc_shiftbits(x->w[x->len-1],p);
    }
    else
    {
        for (i=1;i<=r;i++)
            owc_pmul(pr_owc, x,pr_owc->base2,x);
        owc_pmul(pr_owc, x,owc_shiftbits((owc_small)1,p),x);
    }
}



static owc_small qdiv(owc_large u,owc_large v)
{
    owc_large lq,x=u;
    x-=v;
    if (x<v)
        return 1;
    x-=v;
    if (x<v)
        return 2;
    x-=v;
    if (x<v)
        return 3;
    x-=v;
    if (x<v)
        return 4;
    x-=v;
    if (x<v)
        return 5;
    x-=v;
    if (x<v)
        return 6;
    x-=v;
    if (x<v)
        return 7;
    x-=v;
    if (x<v)
        return 8;

    lq=8+x/v;
    if (lq>=BASE_LIMMIT)
        return 0;
    return (owc_small)lq;
}

int invmodp(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN z)
{

    int s,n,iter;
    owc_small r,a,b,c,d;
    owc_small q,m,sr;
    
    union doubleword uu,vv;
    owc_large u,v,lr;
    
    
    BOOL last,dplus=TRUE;
    OWC_BN t;

    copy(x,pr_owc->tmp1);
    copy(y,pr_owc->tmp2);
    s=exsign(pr_owc->tmp1);
    insign(PLUS,pr_owc->tmp1);
    insign(PLUS,pr_owc->tmp2);
    convert(pr_owc, 1,pr_owc->tmp3);
    zero(pr_owc->tmp4);
    last=FALSE;
    a=b=c=d=0;
    iter=0;
    
    while (size(pr_owc->tmp2)!=0)
    {
        if (b==0)
        {
            divide(pr_owc, pr_owc->tmp1,pr_owc->tmp2,pr_owc->tmp5);
            t=pr_owc->tmp1;
            pr_owc->tmp1=pr_owc->tmp2;
            pr_owc->tmp2=t;    /* swap(pr_owc->tmp1,pr_owc->tmp2) */
            multiply(pr_owc, pr_owc->tmp4,pr_owc->tmp5,pr_owc->tmp0);
            add(pr_owc, pr_owc->tmp3,pr_owc->tmp0,pr_owc->tmp3);
            t=pr_owc->tmp3;
            pr_owc->tmp3=pr_owc->tmp4;
            pr_owc->tmp4=t;
            iter++;
        }
        else
        {
            owc_pmul(pr_owc, pr_owc->tmp1,c,pr_owc->tmp5);
            owc_pmul(pr_owc, pr_owc->tmp1,a,pr_owc->tmp1);
            owc_pmul(pr_owc, pr_owc->tmp2,b,pr_owc->tmp0);
            owc_pmul(pr_owc, pr_owc->tmp2,d,pr_owc->tmp2);
            
            if (!dplus)
            {
                owc_psub(pr_owc, pr_owc->tmp0,pr_owc->tmp1,pr_owc->tmp1);
                owc_psub(pr_owc, pr_owc->tmp5,pr_owc->tmp2,pr_owc->tmp2);
            }
            else
            {
                owc_psub(pr_owc, pr_owc->tmp1,pr_owc->tmp0,pr_owc->tmp1);
                owc_psub(pr_owc, pr_owc->tmp2,pr_owc->tmp5,pr_owc->tmp2);
            }
            owc_pmul(pr_owc, pr_owc->tmp3,c,pr_owc->tmp5);
            owc_pmul(pr_owc, pr_owc->tmp3,a,pr_owc->tmp3);
            owc_pmul(pr_owc, pr_owc->tmp4,b,pr_owc->tmp0);
            owc_pmul(pr_owc, pr_owc->tmp4,d,pr_owc->tmp4);
            
            if (a==0)
                copy(pr_owc->tmp0,pr_owc->tmp3);
            else
                owc_padd(pr_owc, pr_owc->tmp3,pr_owc->tmp0,pr_owc->tmp3);
            owc_padd(pr_owc, pr_owc->tmp4,pr_owc->tmp5,pr_owc->tmp4);
        }
        if (size(pr_owc->tmp2)==0)
            break;
        
        n=(int)pr_owc->tmp1->len;
        if (n==1)
        {
            last=TRUE;
            u=pr_owc->tmp1->w[0];
            v=pr_owc->tmp2->w[0];
        }
        else
        {
            m=pr_owc->tmp1->w[n-1]+1;
            if (pr_owc->base==0)
            {
                if (n>2 && m!=0)
                {
                    uu.h[OWC_TOP]=muldvm(pr_owc->tmp1->w[n-1],pr_owc->tmp1->w[n-2],m,&sr);
                    uu.h[OWC_BOTTOM]=muldvm(sr,pr_owc->tmp1->w[n-3],m,&sr);
                    vv.h[OWC_TOP]=muldvm(pr_owc->tmp2->w[n-1],pr_owc->tmp2->w[n-2],m,&sr);
                    vv.h[OWC_BOTTOM]=muldvm(sr,pr_owc->tmp2->w[n-3],m,&sr);
                }
                else
                {
                    uu.h[OWC_TOP]=pr_owc->tmp1->w[n-1];
                    uu.h[OWC_BOTTOM]=pr_owc->tmp1->w[n-2];
                    vv.h[OWC_TOP]=pr_owc->tmp2->w[n-1];
                    vv.h[OWC_BOTTOM]=pr_owc->tmp2->w[n-2];
                    if (n==2)
                        last=TRUE;
                }
                u=uu.d;
                v=vv.d;
            }
            else
            {
                if (n>2)
                {
                    u=muldiv(pr_owc->tmp1->w[n-1],pr_owc->base,pr_owc->tmp1->w[n-2],m,&sr);
                    u=u*pr_owc->base+muldiv(sr,pr_owc->base,pr_owc->tmp1->w[n-3],m,&sr);
                    v=muldiv(pr_owc->tmp2->w[n-1],pr_owc->base,pr_owc->tmp2->w[n-2],m,&sr);
                    v=v*pr_owc->base+muldiv(sr,pr_owc->base,pr_owc->tmp2->w[n-3],m,&sr);
                }
                else
                {
                    u=(owc_large)pr_owc->base*pr_owc->tmp1->w[n-1]+pr_owc->tmp1->w[n-2];
                    v=(owc_large)pr_owc->base*pr_owc->tmp2->w[n-1]+pr_owc->tmp2->w[n-2];
                    last=TRUE;
                }
            }
        }
        
        dplus=TRUE;
        a=1; b=0; c=0; d=1;
        
        for(;;)
        {
            if (last)
            {
                if (v==0)
                    break;
                q=qdiv(u,v);
                if (q==0)
                    break;
            }
            else
            {
                if (dplus)
                {
                    if ((owc_small)(v-c)==0 || (owc_small)(v+d)==0)
                        break;
                    
                    q=qdiv(u+a,v-c);
                    
                    if (q==0)
                        break;
                    
                    if (q!=qdiv(u-b,v+d))
                        break;
                }
                else
                {
                    if ((owc_small)(v+c)==0 || (owc_small)(v-d)==0)
                        break;
                    q=qdiv(u-a,v+c);
                    if (q==0)
                        break;
                    if (q!=qdiv(u+b,v-d))
                        break;
                }
            }
            
            if (q==1)
            {
                if ((owc_small)(b+d) >= BASE_LIMMIT)
                    break;
                r=a+c;  a=c; c=r;
                r=b+d;  b=d; d=r;
                lr=u-v; u=v; v=lr;
            }
            else
            {
                if (q>=(BASE_LIMMIT-b)/d)
                    break;
                r=a+q*c;  a=c; c=r;
                r=b+q*d;  b=d; d=r;
                lr=u-q*v; u=v; v=lr;
            }
            iter++;
            dplus=!dplus;
        }
        iter%=2;
        
    }
    
    if (s==MINUS)
        iter++;
    if (iter%2==1)
        subtract(pr_owc, y,pr_owc->tmp3,pr_owc->tmp3);
    
    copy(pr_owc->tmp3,z);
    
    return (size(pr_owc->tmp1));
}

void powmod(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN n,OWC_BN w)
{
    owc_small norm;
    BOOL mty;

    mty=TRUE;
    
    if (pr_owc->base!=pr_owc->base2)
    {
        if (size(n)<2 || sgcd(n->w[0],pr_owc->base)!=1)
            mty=FALSE;
    }
    else
        if (subdivisible(pr_owc, n,2))
            mty=FALSE;
    
    if (!mty)
    {
        copy(y,pr_owc->tmp1);
        copy(x,pr_owc->tmp3);
        zero(w);
        if (size(pr_owc->tmp3)==0)
        {
            return;
        }
        convert(pr_owc, 1,w);
        if (size(pr_owc->tmp1)==0)
        {
            return;
        }
        if (size(pr_owc->tmp1)<0)
            return ;
        if (w==n)
            return ;
        
        norm=normalise(pr_owc, n,n);
        divide(pr_owc, pr_owc->tmp3,n,n);
        for(;;)
        {
            
            if (subdiv(pr_owc, pr_owc->tmp1,2,pr_owc->tmp1)!=0)
                mad(pr_owc, w,pr_owc->tmp3,pr_owc->tmp3,n,n,w);
            if (size(pr_owc->tmp1)==0)
                break;
            mad(pr_owc, pr_owc->tmp3,pr_owc->tmp3,pr_owc->tmp3,n,n,pr_owc->tmp3);
        }
        if (norm!=1)
        {
            owc_sdiv(pr_owc, n,norm,n);
            divide(pr_owc, w,n,n);
        }
    }
    else
    {
        prepare_monty(pr_owc,  n);
        nres(pr_owc,  x,pr_owc->tmp3);
        nres_powmod(pr_owc, pr_owc->tmp3,y,w);
        redc(pr_owc,  w,w);
    }
}

int owc_window(owcrypt *pr_owc, OWC_BN x,int i,int *nbs,int * nzs,int window_size)
{
    int j,r,w;
    w=window_size;

    *nbs=1;
    *nzs=0;
    if (!owc_testbit(pr_owc, x,i))
        return 0;

    if (i-w+1<0)
        w=i+1;
    
    r=1;
    for (j=i-1;j>i-w;j--)
    {
        (*nbs)++;
        r*=2;
        if (owc_testbit(pr_owc, x,j))
            r+=1;
        if (r%4==0)
        {
            r/=4;
            *nbs-=2;
            *nzs=2;
            break;
        }
    }
    if (r%2==0)
    {
        r/=2;
        *nzs=1;
        (*nbs)--;
    }
    return r;
}

void nres_powmod(owcrypt *pr_owc, OWC_BN x,OWC_BN y,OWC_BN w)
{
    int i,j,k,t,nb,nbw,nzs,n;
    OWC_BN table[16];

    copy(y,pr_owc->tmp1);
    copy(x,pr_owc->tmp3);
    
    zero(w);
    if (size(x)==0)
    {
        if (size(pr_owc->tmp1)==0)
        {
            copy(pr_owc->one,w);
        }
        return;
    }
    
    copy(pr_owc->one,w);
    if (size(pr_owc->tmp1)==0)
    {
        return;
    }
    
    if (size(pr_owc->tmp1)<0) return ;

    if (pr_owc->base==pr_owc->base2)
    {
        table[0]=pr_owc->tmp3; table[1]=pr_owc->tmp4; table[2]=pr_owc->tmp5; table[3]=pr_owc->tmp14;
        table[4]=NULL;  table[5]=pr_owc->tmp6; table[6]=pr_owc->tmp15; table[7]=pr_owc->tmp8;
        table[8]=NULL;  table[9]=NULL;  table[10]=pr_owc->tmp9; table[11]=pr_owc->tmp10;
        table[12]=NULL; table[13]=pr_owc->tmp11; table[14]=pr_owc->tmp12; table[15]=pr_owc->tmp13;
        
        nres_modmult(pr_owc,  pr_owc->tmp3,pr_owc->tmp3,pr_owc->tmp2);  /* x^2 */
        n=15;
        j=0;
        do
        {
            t=1; k=j+1;
            while (table[k]==NULL) {k++; t++;}
            copy(table[j],table[k]);
            for (i=0;i<t;i++)
                nres_modmult(pr_owc,  table[k],pr_owc->tmp2,table[k]);
            j=k;
        } while (j<n);
        
        nb=logb2(pr_owc, pr_owc->tmp1);
        copy(pr_owc->tmp3,w);
        if (nb>1) for (i=nb-2;i>=0;)
        {
            n=owc_window(pr_owc, pr_owc->tmp1,i,&nbw,&nzs,5);
            for (j=0;j<nbw;j++)
                nres_modmult(pr_owc,  w,w,w);
            if (n>0)
                nres_modmult(pr_owc,  w,table[n/2],w);
            i-=nbw;
            if (nzs)
            {
                for (j=0;j<nzs;j++)
                    nres_modmult(pr_owc,  w,w,w);
                i-=nzs;
            }
        }
    }
    else
    {
        copy(pr_owc->tmp3,pr_owc->tmp2);
        for(;;)
        {
            if (subdiv(pr_owc, pr_owc->tmp1,2,pr_owc->tmp1)!=0)
                nres_modmult(pr_owc,  w,pr_owc->tmp2,w);
            if (size(pr_owc->tmp1)==0)
                break;
            nres_modmult(pr_owc,  pr_owc->tmp2,pr_owc->tmp2,pr_owc->tmp2);
        }
    }
}

