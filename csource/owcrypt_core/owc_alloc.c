
#include "owcrypt_core.h"
#include <stdlib.h>

void *owc_alloc(owcrypt *pr_owc,  int num,int size)
{
    char *p;
    if (pr_owc==NULL) 
    {
        p=(char *)calloc(num,size);
        return (void *)p;
    }
 
    p=(char *)calloc(num,size);
    if (p==NULL)
        return NULL;
    return (void *)p;

}

void owc_free(void *addr)
{
    if (addr==NULL)
        return;
    free(addr);
    return;
}

