/*******************************************************************************
*   Bytecoin Wallet for Ledger Nano S
*   (c) 2018 - 2019 The Bytecoin developers
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "os.h"
#include "cx.h"
#include "bytecoin_crypto.h"
#include "bytecoin_fe.h"
#include "bytecoin_debug.h"

static const uint8_t C_ED25519_G[] = {
    //uncompressed
    0x04,
    //x
    0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe, 0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
    0x69, 0x2c, 0xc7, 0x60, 0x95, 0x25, 0xa7, 0xb2, 0xc9, 0x56, 0x2d, 0x60, 0x8f, 0x25, 0xd5, 0x1a,
    //y
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58
};

static const uint8_t C_ED25519_H[] = {
    0x04,
    0x61, 0x88, 0xae, 0x40, 0x72, 0x00, 0x4c, 0xb8, 0x5d, 0x56, 0xab, 0x7e, 0xf9, 0xcf, 0x37, 0x71,
    0x6a, 0xcc, 0xac, 0xce, 0x86, 0x27, 0xee, 0xfa, 0x68, 0x74, 0x66, 0x49, 0x38, 0x6f, 0xd8, 0x73,
    0x14, 0x1f, 0x9c, 0xd3, 0x0d, 0x3a, 0x17, 0x2c, 0xa9, 0xcf, 0x54, 0x41, 0xd5, 0x51, 0x72, 0x6c,
    0xea, 0xd0, 0xad, 0xf1, 0x9f, 0xdc, 0xea, 0x2a, 0xaf, 0x99, 0x37, 0x15, 0x70, 0x59, 0x65, 0x8b
};

static const uint8_t C_ED25519_ORDER[] = {
    //l: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED
};

const uint8_t C_ED25519_FIELD[] = {
   //q:  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};

const uint8_t C_ED25519_2_256[] = {
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xc6, 0xef, 0x5b, 0xf4, 0x73, 0x7d, 0xcf, 0x70, 0xd6, 0xec, 0x31, 0x74, 0x8d, 0x98, 0x95, 0x1d
};

//static
void compress_point(decompressed_point_t* point, elliptic_curve_point_t* result)
{
    cx_edward_compress_point(CX_CURVE_Ed25519, point->data, sizeof(point->data));
    os_memmove(result->data, &point->data[1], sizeof(result->data));
}

static
void decompress_point(const elliptic_curve_point_t* point, decompressed_point_t* result)
{
    result->data[0] = 0x02;
    os_memmove(&result->data[1], point->data, sizeof(point->data));
    cx_edward_decompress_point(CX_CURVE_Ed25519, result->data, sizeof(result->data));
}

void reverse(uint8_t* reversed, const uint8_t* data, size_t len)
{
    uint8_t temp;
    for (size_t i = 0; i < len/2; ++i)
    {
        temp = data[i];
        reversed[i] = data[len - 1 - i];
        reversed[len - 1 - i] = temp;
    }
}

void keccak_init(keccak_hasher_t* hasher)
{
    crypto_keccak_init(hasher, 256, 1);
}

void keccak_update(keccak_hasher_t* hasher, const void* buf, size_t len)
{
    crypto_keccak_update(hasher, buf, len);
}

void keccak_update_varint(keccak_hasher_t* hasher, uint64_t value)
{
    uint8_t buf[(sizeof(value) * 8 + 6) / 7];
    const uint32_t len = encode_varint(value, buf);
    keccak_update(hasher, buf, len);
}

void keccak_update_byte(keccak_hasher_t* hasher, uint8_t value)
{
    keccak_update(hasher, &value, sizeof(value));
}

void keccak_final(keccak_hasher_t* hasher, hash_t* result)
{
    crypto_keccak_final(hasher, result->data, sizeof(result->data));
}

void keccak_final_to_scalar(keccak_hasher_t* hasher, elliptic_curve_scalar_t* result)
{
    hash_t hash;
    keccak_final(hasher, &hash);
    reduce32(&hash, result);
}

void keccak_final_to_scalar64(keccak_hasher_t* hasher, elliptic_curve_scalar_t* result)
{
    hash_t hash;
    keccak_final(hasher, &hash);
    reduce64(&hash, result);
}

void keccak_final_to_good_point(keccak_hasher_t* hasher, elliptic_curve_point_t* result)
{
    hash_t hash;
    keccak_final(hasher, &hash);
    elliptic_curve_point_t bad_point;
    ge_fromfe_frombytes(&hash, &bad_point);
    ecmul_8(&bad_point, result);
}

void fast_hash(const void* buf, size_t len, hash_t* result)
{
    keccak_hasher_t hasher;
    keccak_init(&hasher);
    keccak_update(&hasher, buf, len);
    keccak_final(&hasher, result);
}

void hash_to_scalar(const void* buf, size_t len, elliptic_curve_scalar_t* result)
{
    hash_t hash;
    fast_hash(buf, len, &hash);
    reduce32(&hash, result);
}

void hash_to_scalar64(const void *buf, size_t len, elliptic_curve_scalar_t *result)
{
    hash_t left_hash;
    fast_hash(buf, len, &left_hash);
    reduce64(&left_hash, result);
}

size_t encode_varint(uint64_t value, uint8_t* buf)
{
    size_t len = 0;
    while(value >= 0x80)
    {
        buf[len++] = (value & 0x7F) | 0x80;
        value >>= 7;
    }
    buf[len++] = value;
    return len;
}

void reduce32(const hash_t* h, elliptic_curve_scalar_t* result)
{
    reverse(result->data, h->data, sizeof(h->data));
    cx_math_modm(result->data, sizeof(result->data), C_ED25519_ORDER, sizeof(C_ED25519_ORDER));
}

void reduce64(const hash_t* h, elliptic_curve_scalar_t* result)
{
    const hash_t* left_hash = h;
    hash_t right_hash;
    fast_hash(left_hash->data, sizeof(left_hash->data), &right_hash);
    secret_key_t left;
    reduce32(left_hash, &left);
    secret_key_t right;
    reduce32(&right_hash, &right);

    elliptic_curve_scalar_t sc_2_256;
    os_memmove(sc_2_256.data, C_ED25519_2_256, sizeof(C_ED25519_2_256));

    ecmulm(&right, &sc_2_256, result);
    ecaddm(result, &left, result);
}

void invert32(const elliptic_curve_scalar_t *a, elliptic_curve_scalar_t* result)
{
    os_memmove(result->data, a->data, sizeof(a->data));
    cx_math_invprimem(result->data, a->data, C_ED25519_ORDER, sizeof(C_ED25519_ORDER));
}

void ecmulm(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result)
{
    cx_math_multm(result->data, a->data, b->data, C_ED25519_ORDER, sizeof(result->data));
}

void ecmul(const elliptic_curve_point_t* point, const elliptic_curve_scalar_t* scalar, elliptic_curve_point_t* result)
{
    decompressed_point_t Pxy;
    decompress_point(point, &Pxy);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy.data, sizeof(Pxy.data), scalar->data, sizeof(scalar->data));
    compress_point(&Pxy, result);
}

static
void d_ecmul(decompressed_point_t* point, const elliptic_curve_scalar_t* scalar, elliptic_curve_point_t* result)
{
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, point->data, sizeof(point->data), scalar->data, sizeof(scalar->data));
    compress_point(point, result);
}

void ecmul_G(const elliptic_curve_scalar_t* scalar, elliptic_curve_point_t* result)
{
    decompressed_point_t Pxy;
    os_memmove(Pxy.data, C_ED25519_G, sizeof(Pxy.data));
    d_ecmul(&Pxy, scalar, result);
}

void ecmul_H(const elliptic_curve_scalar_t* scalar, elliptic_curve_point_t* result)
{
    decompressed_point_t Pxy;
    os_memmove(Pxy.data, C_ED25519_H, sizeof(Pxy.data));
    d_ecmul(&Pxy, scalar, result);
}

void ecadd(const elliptic_curve_point_t* P, const elliptic_curve_point_t* Q, elliptic_curve_point_t* result)
{
    decompressed_point_t Pxy;
    decompressed_point_t Qxy;
    decompress_point(P, &Pxy);
    decompress_point(Q, &Qxy);
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy.data, Pxy.data, Qxy.data, sizeof(Pxy.data));
    compress_point(&Pxy, result);
}

void d_ecadd(const decompressed_point_t* P, const decompressed_point_t* Q, elliptic_curve_point_t* result)
{
    decompressed_point_t Rxy;
    cx_ecfp_add_point(CX_CURVE_Ed25519, Rxy.data, P->data, Q->data, sizeof(Rxy.data));
    compress_point(&Rxy, result);
}

void ecsub(const elliptic_curve_point_t* P, const elliptic_curve_point_t* Q, elliptic_curve_point_t* result)
{
    decompressed_point_t Pxy;
    decompressed_point_t minus_Qxy;
    decompress_point(P, &Pxy);
    decompress_point(Q, &minus_Qxy);
    cx_math_subm(&minus_Qxy.data[1], C_ED25519_FIELD, &minus_Qxy.data[1], C_ED25519_FIELD, sizeof(C_ED25519_FIELD));
    d_ecadd(&Pxy, &minus_Qxy, result);
}

void ecadd_G(const elliptic_curve_point_t* P, elliptic_curve_point_t* result)
{
    decompressed_point_t Pxy;
    decompress_point(P, &Pxy);

    decompressed_point_t Qxy;
    os_memmove(Qxy.data, C_ED25519_G, sizeof(Qxy.data));

    d_ecadd(&Qxy, &Pxy, result);
}

void ecaddm(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result)
{
    cx_math_addm(result->data, a->data, b->data, C_ED25519_ORDER, sizeof(result->data));
}

void ecsubm(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result)
{
    cx_math_subm(result->data, a->data, b->data, C_ED25519_ORDER, sizeof(result->data));
}

static
void hash_to_bad_point(const void* buf, uint32_t len, elliptic_curve_point_t* result)
{
    hash_t hash;
    fast_hash(buf, len, &hash);
    ge_fromfe_frombytes(&hash, result);
}

static
void hash_to_good_point(const void* buf, uint32_t len, elliptic_curve_point_t* result)
{
    elliptic_curve_point_t bp;
    hash_to_bad_point(buf, len, &bp);
    ecmul_8(&bp, result);
}

void hash_point_to_good_point(const elliptic_curve_point_t* p, elliptic_curve_point_t* result)
{
    hash_to_good_point(p->data, sizeof(p->data), result);
}

void hash_scalar_to_good_point(const elliptic_curve_scalar_t* s, elliptic_curve_point_t* result)
{
    uint8_t buf[sizeof(s->data)];
    reverse(buf, s->data, sizeof(buf));
    hash_to_good_point(buf, sizeof(buf), result);
}

void ecmul_8(const elliptic_curve_point_t* P, elliptic_curve_point_t* result)
{
    decompressed_point_t d_result;
    decompress_point(P, &d_result);
    cx_ecfp_add_point(CX_CURVE_Ed25519, d_result.data, d_result.data, d_result.data, sizeof(d_result.data));
    cx_ecfp_add_point(CX_CURVE_Ed25519, d_result.data, d_result.data, d_result.data, sizeof(d_result.data));
    cx_ecfp_add_point(CX_CURVE_Ed25519, d_result.data, d_result.data, d_result.data, sizeof(d_result.data));
    compress_point(&d_result, result);
}
