#ifndef BYTECOIN_FE_H
#define BYTECOIN_FE_H

#include "bytecoin_crypto.h"

void ge_fromfe_frombytes(const hash_t* bytes, elliptic_curve_point_t* result);
void old_ge_fromfe_frombytes(const hash_t* bytes, elliptic_curve_point_t* result);

#endif // BYTECOIN_FE_H
