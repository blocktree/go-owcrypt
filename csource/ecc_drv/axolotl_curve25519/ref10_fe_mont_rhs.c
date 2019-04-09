#include "ref10_fe.h"

void REF10_fe_mont_rhs(REF10_fe v2, const REF10_fe u) {
  REF10_fe A, one;
  REF10_fe u2, Au, inner;

  REF10_fe_1(one);
  REF10_fe_0(A);
  A[0] = 486662;                     /* A = 486662 */

  REF10_fe_sq(u2, u);                      /* u^2 */
  REF10_fe_mul(Au, A, u);                  /* Au */
  REF10_fe_add(inner, u2, Au);             /* u^2 + Au */
  REF10_fe_add(inner, inner, one);         /* u^2 + Au + 1 */
  REF10_fe_mul(v2, u, inner);              /* u(u^2 + Au + 1) */
}

