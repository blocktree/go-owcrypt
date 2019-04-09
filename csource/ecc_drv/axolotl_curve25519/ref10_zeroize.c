#include "ref10_zeroize.h"

void REF10_zeroize(unsigned char* b, size_t len)
{
  size_t count = 0;
  volatile unsigned char *p = b;

  for (count = 0; count < len; count++)
    p[count] = 0;
}

void REF10_zeroize_stack(void)
{
  unsigned char m[ZEROIZE_STACK_SIZE];
  REF10_zeroize(m, ZEROIZE_STACK_SIZE);
}
