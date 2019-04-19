#ifndef BYTECOIN_BASE58_H
#define BYTECOIN_BASE58_H

#include <stdint.h>
#include <stddef.h>

size_t encode_base58(const uint8_t* data, size_t data_len, char* result, size_t result_len);

#endif // BYTECOIN_BASE58_H
