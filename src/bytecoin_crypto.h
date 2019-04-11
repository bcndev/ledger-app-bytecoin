#ifndef BYTECOIN_CRYPTO_H
#define BYTECOIN_CRYPTO_H

#include "os.h"
#include "cx.h"
#include "bytecoin_keccak.h"

typedef struct hash_s
{
    uint8_t data[32];
} hash_t;

//typedef struct hash64_s
//{
//    uint8_t data[64];
//} hash64_t;

typedef struct elliptic_curve_point_s
{
    uint8_t data[32];
} elliptic_curve_point_t;

typedef struct elliptic_curve_scalar_s
{
    uint8_t data[32];
} elliptic_curve_scalar_t;

typedef struct signature_s
{
    elliptic_curve_scalar_t c;
    elliptic_curve_scalar_t r;
} signature_t;

//typedef struct chacha_key_s
//{
//    uint8_t data[32];
//} chacha_key_t;

typedef elliptic_curve_point_t  keyimage_t;
typedef elliptic_curve_point_t  public_key_t;
typedef elliptic_curve_scalar_t secret_key_t;

//void reverse32(uint8_t* reversed, const uint8_t* data);
void reverse(uint8_t* reversed, const uint8_t* data, size_t len);
size_t encode_varint(uint64_t value, uint8_t* buf);

void generate_random_bytes(uint8_t* buf, size_t len);

void fast_hash(const void* buf, size_t len, hash_t* result);
void hash_to_scalar(const void* buf, size_t len, elliptic_curve_scalar_t* result);
void hash_to_scalar64(const void* buf, size_t len, elliptic_curve_scalar_t* result);

//elliptic_curve_point_t hash_to_good_point(const void* buf, uint32_t len);
//elliptic_curve_point_t hash_to_bad_point(const void* buf, uint32_t len);
void hash_point_to_good_point(const elliptic_curve_point_t* p, elliptic_curve_point_t* result);
void hash_scalar_to_good_point(const elliptic_curve_scalar_t* s, elliptic_curve_point_t* result);

void keccak_init(keccak_hasher_t* hasher);
void keccak_update(keccak_hasher_t* hasher, const void* buf, size_t len);
void keccak_update_varint(keccak_hasher_t* hasher, uint64_t value);
void keccak_update_byte(keccak_hasher_t* hasher, uint8_t value);
void keccak_final(keccak_hasher_t* hasher, hash_t* result);
void keccak_final_to_scalar(keccak_hasher_t* hasher, elliptic_curve_scalar_t* result);
void keccak_final_to_scalar64(keccak_hasher_t* hasher, elliptic_curve_scalar_t* result);
void keccak_final_to_good_point(keccak_hasher_t* hasher, elliptic_curve_point_t* result);

void reduce32(const hash_t* hash, elliptic_curve_scalar_t* result);
void reduce64(const hash_t* left_hash, elliptic_curve_scalar_t* result);
void invert32(const elliptic_curve_scalar_t* a, elliptic_curve_scalar_t* result);

void ecmulm(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result);
void ecaddm(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result);
void ecsubm(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result);
//elliptic_curve_scalar_t ecpowm(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* e);
void ecmul(const elliptic_curve_point_t* P, const elliptic_curve_scalar_t* scalar, elliptic_curve_point_t* result);
void ecadd(const elliptic_curve_point_t* P, const elliptic_curve_point_t* Q, elliptic_curve_point_t* result);
void ecsub(const elliptic_curve_point_t* P, const elliptic_curve_point_t* Q, elliptic_curve_point_t* result);

void ecadd_G(const elliptic_curve_point_t* P, elliptic_curve_point_t* result);

void ecmul_G(const elliptic_curve_scalar_t* scalar, elliptic_curve_point_t* result);
void ecmul_H(const elliptic_curve_scalar_t* scalar, elliptic_curve_point_t* result);
void ecmul_8(const elliptic_curve_point_t* P, elliptic_curve_point_t* result);

typedef struct decompressed_point_s
{
    uint8_t data[65];
} decompressed_point_t;

void compress_point(decompressed_point_t* point, elliptic_curve_point_t* result);

#endif // BYTECOIN_CRYPTO_H
