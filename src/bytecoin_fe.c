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

#include "bytecoin_fe.h"
#include "bytecoin_vars.h"

extern const uint8_t C_ED25519_FIELD[];

// A = 486662
static const uint8_t C_fe_ma2[] = {
    /* -A^2
     *  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffc8db3de3c9
     */
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc8, 0xdb, 0x3d, 0xe3, 0xc9
};

static const uint8_t C_fe_ma[] = {
    /* -A
     *  0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff892e7
     */
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x92, 0xe7
};

static const uint8_t C_fe_qm5div8[] = {
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd
};

static const uint8_t C_fe_fffb1[] = {

    /* sqrt(-2 * A * (A + 2))
     * 0x7e71fbefdad61b1720a9c53741fb19e3d19404a8b92a738d22a76975321c41ee
     */
    0x7e, 0x71, 0xfb, 0xef, 0xda, 0xd6, 0x1b, 0x17, 0x20, 0xa9, 0xc5, 0x37, 0x41, 0xfb, 0x19, 0xe3,
    0xd1, 0x94, 0x04, 0xa8, 0xb9, 0x2a, 0x73, 0x8d, 0x22, 0xa7, 0x69, 0x75, 0x32, 0x1c, 0x41, 0xee
};
static const uint8_t C_fe_fffb2[] = {
    /* sqrt(2 * A * (A + 2))
     * 0x4d061e0a045a2cf691d451b7c0165fbe51de03460456f7dfd2de6483607c9ae0
     */
    0x4d, 0x06, 0x1e, 0x0a, 0x04, 0x5a, 0x2c, 0xf6, 0x91, 0xd4, 0x51, 0xb7, 0xc0, 0x16, 0x5f, 0xbe,
    0x51, 0xde, 0x03, 0x46, 0x04, 0x56, 0xf7, 0xdf, 0xd2, 0xde, 0x64, 0x83, 0x60, 0x7c, 0x9a, 0xe0
};

static const uint8_t C_fe_fffb3[] = {
    /* sqrt(-sqrt(-1) * A * (A + 2))
     * 674a110d14c208efb89546403f0da2ed4024ff4ea5964229581b7d8717302c66
     */
    0x67, 0x4a, 0x11, 0x0d, 0x14, 0xc2, 0x08, 0xef, 0xb8, 0x95, 0x46, 0x40, 0x3f, 0x0d, 0xa2, 0xed,
    0x40, 0x24, 0xff, 0x4e, 0xa5, 0x96, 0x42, 0x29, 0x58, 0x1b, 0x7d, 0x87, 0x17, 0x30, 0x2c, 0x66

};
static const uint8_t C_fe_fffb4[] = {
    /* sqrt(sqrt(-1) * A * (A + 2))
     * 1a43f3031067dbf926c0f4887ef7432eee46fc08a13f4a49853d1903b6b39186
     */
   0x1a, 0x43, 0xf3, 0x03, 0x10, 0x67, 0xdb, 0xf9, 0x26, 0xc0, 0xf4, 0x88, 0x7e, 0xf7, 0x43, 0x2e,
   0xee, 0x46, 0xfc, 0x08, 0xa1, 0x3f, 0x4a, 0x49, 0x85, 0x3d, 0x19, 0x03, 0xb6, 0xb3, 0x91, 0x86

};

static const uint8_t C_fe_sqrtm1[] = {
    /* sqrt(2 * A * (A + 2))
     * 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
     */
    0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b, 0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7,
    0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78, 0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0
};

#if 0

static const uint8_t C_ONE[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static
void reduce32_field(const hash_t* h, elliptic_curve_scalar_t* result)
{
    reverse(result->data, h->data, sizeof(h->data));
    cx_math_modm(result->data, sizeof(result->data), C_ED25519_FIELD, /*sizeof(C_ED25519_FIELD)*/32);
}

static inline
void mulm_field(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result)
{
    cx_math_multm(result->data, a->data, b->data, C_ED25519_FIELD, sizeof(result->data));
}

static inline
void addm_field(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result)
{
    cx_math_addm(result->data, a->data, b->data, C_ED25519_FIELD, sizeof(result->data));
}

static inline
void subm_field(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* b, elliptic_curve_scalar_t* result)
{
    cx_math_subm(result->data, a->data, b->data, C_ED25519_FIELD, sizeof(result->data));
}

static inline
void powm_field(const elliptic_curve_scalar_t* a, const elliptic_curve_scalar_t* e, elliptic_curve_scalar_t* result)
{
    cx_math_powm(result->data, a->data, e->data, sizeof(e->data), C_ED25519_FIELD, sizeof(result->data));
}

static inline
bool is_zero(const elliptic_curve_scalar_t* a)
{
    return cx_math_is_zero(a->data, sizeof(a->data));
}

static
void divpowm1_field(const elliptic_curve_scalar_t* u, const elliptic_curve_scalar_t* v, elliptic_curve_scalar_t* result)
{
    elliptic_curve_scalar_t s[3];

#define v2 s[0]
#define v3 s[1]
    mulm_field(v, v, &v2);
    mulm_field(&v2, v, &v3);
#undef v2
#define v6 s[0]
#define v7 s[2]
    mulm_field(&v3, &v3, &v6);
    mulm_field(&v6, v, &v7);  // v7 = v^7
#undef v6
#define uv7 s[0]
    mulm_field(&v7, u, &uv7); // uv7 = uv^7
#undef v7
#define uv7qm5div8 s[2]
    powm_field(&uv7, (const elliptic_curve_scalar_t*)C_fe_qm5div8, &uv7qm5div8); // uv7qm5div8 = (uv^7)^((q-5)/8)
#undef uv7
#define v3uv7qm5div8 s[0]
    mulm_field(&uv7qm5div8, &v3, &v3uv7qm5div8);
#undef v3
#undef uv7qm5div8
    mulm_field(&v3uv7qm5div8, u, result);  // u^(m+1)v^(-(m+1))
#undef v3uv7qm5div8
}

static inline
void invprimem_field(const elliptic_curve_scalar_t* a, elliptic_curve_scalar_t* result)
{
    cx_math_invprimem(result->data, a->data, C_ED25519_FIELD, sizeof(result->data));
}

static inline
bool is_scalar_negative(const elliptic_curve_scalar_t* a)
{
    return a->data[31] & 1;
}

void ge_fromfe_frombytes(const hash_t* bytes, elliptic_curve_point_t* result)
{
    union
    {
        elliptic_curve_scalar_t s[6];
        decompressed_point_t Pxy;
    } un;

#define s0 un.s[0]
#define s1 un.s[1]
#define s2 un.s[2]
#define s3 un.s[3]
#define s4 un.s[4]
#define s5 un.s[5]

#define u s0
#define sqr_u s1
#define sqr_u_2 s2
    reduce32_field(bytes, &u);
    mulm_field(&u, &u, &sqr_u);          // u^2
    addm_field(&sqr_u, &sqr_u, &sqr_u_2); // 2*u^2
#undef sqr_u
#define w s1
#define sqr_w s3
#define y s4
#define x s5
    addm_field(&sqr_u_2, (const elliptic_curve_scalar_t*)C_ONE, &w);  // w = 2*u^2 + 1
    mulm_field(&w, &w, &sqr_w);                                       // w^2
    mulm_field((const elliptic_curve_scalar_t*)C_fe_ma2, &sqr_u_2, &y); // y = -2*A^2 * u^2
    addm_field(&sqr_w, &y, &x);                                       // x = w^2 - 2*A^2*u^2
#undef sqr_w
#undef y
#define rX s3
#define rX2 s4
    divpowm1_field(&w, &x, &rX);
    mulm_field(&rX, &rX, &rX2);
#define rX2x s4 // reuse in returned value
    mulm_field(&rX2, &x, &rX2x);
#undef rX2 // reused already
#undef x
#define wmrX2x s5
    subm_field(&w, &rX2x, &wmrX2x);

    bool negative = false;
    if (!is_zero(&wmrX2x))
#undef wmrX2x
#define wprX2x s5
    {
        addm_field(&w, &rX2x, &wprX2x);
        if (!is_zero(&wprX2x))
#undef wprX2x
#define rX2xsqrtm1 s5
        {
            mulm_field(&rX2x, (const elliptic_curve_scalar_t*)C_fe_sqrtm1, &rX2xsqrtm1);
#undef rX2x
#define wmrX2xsqrtm1 s4
            subm_field(&w, &rX2xsqrtm1, &wmrX2xsqrtm1);
#undef rX2xsqrtm1
            if (!is_zero(&wmrX2xsqrtm1))
#undef wmrX2xsqrtm1
            {
                mulm_field(&rX, (const elliptic_curve_scalar_t*)C_fe_fffb3, &rX);
            }
            else
                mulm_field(&rX, (const elliptic_curve_scalar_t*)C_fe_fffb4, &rX);
            negative = true;
        }
        else
            mulm_field(&rX, (const elliptic_curve_scalar_t*)C_fe_fffb1, &rX);
    }
    else
        mulm_field(&rX, (const elliptic_curve_scalar_t*)C_fe_fffb2, &rX);

#define z s4
    os_memmove(&z, C_fe_ma, sizeof(C_fe_ma));
    if (!negative)
    {
        mulm_field(&rX, &u, &rX);
#undef u
        mulm_field(&z, &sqr_u_2, &z);
#undef sqr_u_2
    }

    if (is_scalar_negative(&rX) != negative)
       subm_field((const elliptic_curve_scalar_t*)C_ED25519_FIELD, &rX, &rX);

#define rZ s0
#define rY s5
   addm_field(&z, &w, &rZ);
   subm_field(&z, &w, &rY);
#undef w
#undef z
#define inv_rZ s4
   mulm_field(&rX, &rZ, &rX);
   invprimem_field(&rZ, &inv_rZ);
#undef rZ

   un.Pxy.data[0] = 0x04;
   {
       elliptic_curve_scalar_t t;
       mulm_field(&rX, &inv_rZ, &t);
       os_memmove(&un.Pxy.data[1], t.data, sizeof(t.data));
   }
#undef rX
   {
       elliptic_curve_scalar_t t;
       mulm_field(&rY, &inv_rZ, &t);
       os_memmove(&un.Pxy.data[1 + sizeof(t.data)], t.data, sizeof(t.data));
   }
#undef rY
#undef inv_rZ
   compress_point(&un.Pxy, result);
}

#else

void ge_fromfe_frombytes(const hash_t* bytes, elliptic_curve_point_t* result)
{
    #define  MOD (unsigned char *)C_ED25519_FIELD,32
    #define fe_isnegative(f)      (f[31]&1)

//#define USE_IO_BUFFER_INSTEAD_OF_LOCAL_STACK
#ifndef USE_IO_BUFFER_INSTEAD_OF_LOCAL_STACK
    unsigned char u[32], v[32], w[32], x[32], y[32], z[32];
    unsigned char rX[32], rY[32], rZ[32];
#else
#define u   (G_bytecoin_vstate.io_buffer.data+0*32)
#define v   (G_bytecoin_vstate.io_buffer.data+1*32)
#define w   (G_bytecoin_vstate.io_buffer.data+2*32)
#define x   (G_bytecoin_vstate.io_buffer.data+3*32)
#define y   (G_bytecoin_vstate.io_buffer.data+4*32)
#define z   (G_bytecoin_vstate.io_buffer.data+5*32)
#define rX  (G_bytecoin_vstate.io_buffer.data+6*32)
#define rY  (G_bytecoin_vstate.io_buffer.data+7*32)
#define rZ  (G_bytecoin_vstate.io_buffer.data+8*32)

#if BYTECOIN_IO_BUFFER_SIZE < (9*32)
#error  BYTECOIN_IO_BUFFER_SIZE is too small
#endif
#endif

    union {
        unsigned char _Pxy[65];
        struct {
            unsigned char _uv7[32];
            unsigned char  _v3[32];
        };
    } uv;

    #define uv7 uv._uv7
    #define v3 uv._v3

    #define Pxy   uv._Pxy

    unsigned char sign;

    //cx works in BE
    reverse(u,bytes->data, sizeof(bytes->data));
//    os_memmove(u, bytes->data, sizeof(bytes->data));
    cx_math_modm(u, 32, (unsigned char *)C_ED25519_FIELD, 32);

    //go on
    cx_math_multm(v, u, u, MOD);                           /* 2 * u^2 */
    cx_math_addm (v,  v, v, MOD);

    os_memset    (w, 0, 32); w[31] = 1;                   /* w = 1 */
    cx_math_addm (w, v, w,MOD );                          /* w = 2 * u^2 + 1 */
    cx_math_multm(x, w, w, MOD);                          /* w^2 */
    cx_math_multm(y, (unsigned char *)C_fe_ma2, v, MOD);  /* -2 * A^2 * u^2 */
    cx_math_addm (x, x, y, MOD);                          /* x = w^2 - 2 * A^2 * u^2 */

    //inline fe_divpowm1(r->X, w, x);     // (w / x)^(m + 1) => fe_divpowm1(r,u,v)
    #define _u w
    #define _v x
    cx_math_multm(v3, _v,   _v, MOD);
    cx_math_multm(v3,  v3,  _v, MOD);                       /* v3 = v^3 */
    cx_math_multm(uv7, v3,  v3, MOD);
    cx_math_multm(uv7, uv7, _v, MOD);
    cx_math_multm(uv7, uv7, _u, MOD);                     /* uv7 = uv^7 */
    cx_math_powm (uv7, uv7, (unsigned char *)C_fe_qm5div8, 32, MOD); /* (uv^7)^((q-5)/8)*/
    cx_math_multm(uv7, uv7, v3, MOD);
    cx_math_multm(rX,  uv7, w, MOD);                      /* u^(m+1)v^(-(m+1)) */
    #undef _u
    #undef _v

    cx_math_multm(y, rX,rX, MOD);
    cx_math_multm(x, y, x, MOD);
    cx_math_subm(y, w, x, MOD);
    os_memmove(z, C_fe_ma, 32);

    if (!cx_math_is_zero(y,32)) {
     cx_math_addm(y, w, x, MOD);
     if (!cx_math_is_zero(y,32)) {
       goto negative;
     } else {
      cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb1, MOD);
     }
   } else {
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb2, MOD);
   }
   cx_math_multm(rX, rX, u, MOD);  // u * sqrt(2 * A * (A + 2) * w / x)
   cx_math_multm(z, z, v, MOD);        // -2 * A * u^2
   sign = 0;

   goto setsign;

  negative:
   cx_math_multm(x, x, (unsigned char *)C_fe_sqrtm1, MOD);
   cx_math_subm(y, w, x, MOD);
   if (!cx_math_is_zero(y,32)) {
     cx_math_addm(y, w, x, MOD);
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb3, MOD);
   } else {
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb4, MOD);
   }
   // r->X = sqrt(A * (A + 2) * w / x)
   // z = -A
   sign = 1;

 setsign:
   if (fe_isnegative(rX) != sign) {
     //fe_neg(r->X, r->X);
    cx_math_subm(rX, (unsigned char *)C_ED25519_FIELD, rX, MOD);
   }
   cx_math_addm(rZ, z, w, MOD);
   cx_math_subm(rY, z, w, MOD);
   cx_math_multm(rX, rX, rZ, MOD);

   cx_math_invprimem(u, rZ, MOD);
   Pxy[0] = 0x04;
   cx_math_multm(&Pxy[1],    rX, u, MOD);
   cx_math_multm(&Pxy[1+32], rY, u, MOD);
   cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
   os_memmove(result->data, &Pxy[1], 32);

    #undef u
    #undef v
    #undef w
    #undef x
    #undef y
    #undef z
    #undef rX
    #undef rY
    #undef rZ

    #undef uv7
    #undef v3

    #undef Pxy
}

#endif
