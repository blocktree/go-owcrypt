#ifndef __ZEROIZE_H__
#define __ZEROIZE_H__

#include <stdlib.h>

#define ZEROIZE_STACK_SIZE 1024

void REF10_zeroize(unsigned char* b, size_t len);

void REF10_zeroize_stack(void);

#endif
