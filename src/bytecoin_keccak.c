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
#include "bytecoin_keccak.h"

typedef uint64_t keccak_lane_t;

#ifndef LITTLE_ENDIAN
/** Function to load a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static
uint64_t load64(const uint8_t *x)
{
    uint64_t u = 0;

    for(int i = 7; i >= 0; --i)
    {
        u <<= 8;
        u |= x[i];
    }
    return u;
}

/** Function to store a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static
void store64(uint8_t *x, uint64_t u)
{
    for(int i = 0; i < 8; ++i)
    {
        x[i] = (uint8_t)u;
        u >>= 8;
    }
}

/** Function to XOR into a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static
void xor64(uint8_t *x, uint64_t u)
{
    for(int i = 0; i < 8; ++i)
    {
        x[i] ^= u;
        u >>= 8;
    }
}
#endif

/*
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
*/

#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))

#ifdef LITTLE_ENDIAN
    #define readLane(x, y)          (((keccak_lane_t*)state)[i(x, y)])
    #define writeLane(x, y, lane)   (((keccak_lane_t*)state)[i(x, y)]) = (lane)
    #define XORLane(x, y, lane)     (((keccak_lane_t*)state)[i(x, y)]) ^= (lane)
#else
    #define readLane(x, y)          load64((uint8_t*)state+sizeof(keccak_lane_t)*i(x, y))
    #define writeLane(x, y, lane)   store64((uint8_t*)state+sizeof(keccak_lane_t)*i(x, y), lane)
    #define XORLane(x, y, lane)     xor64((uint8_t*)state+sizeof(keccak_lane_t)*i(x, y), lane)
#endif

/**
  * Function that computes the linear feedback shift register (LFSR) used to
  * define the round constants (see [Keccak Reference, Section 1.2]).
  */
static
int LFSR86540(uint8_t *LFSR)
{
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

static
void KeccakF1600_StatePermute(void *state)
{
    unsigned int round, x, y, j, t;
    uint8_t LFSRstate = 0x01;

    for(round=0; round<24; round++)
    {
        {   /* === theta step (see [Keccak Reference, Section 2.3.2]) === */
            keccak_lane_t C[5], D;

            /* Compute the parity of the columns */
            for(x=0; x<5; x++)
                C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
            for(x=0; x<5; x++)
            {
                /* Compute the theta effect for a given column */
                D = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
                /* Add the theta effect to the whole column */
                for (y=0; y<5; y++)
                    XORLane(x, y, D);
            }
        }

        {   /* === ro and pi steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) === */
            keccak_lane_t current, temp;
            /* Start at coordinates (1 0) */
            x = 1; y = 0;
            current = readLane(x, y);
            /* Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
            for(t=0; t<24; t++)
            {
                /* Compute the rotation constant r = (t+1)(t+2)/2 */
                unsigned int r = ((t+1)*(t+2)/2)%64;
                /* Compute ((0 1)(2 3)) * (x y) */
                unsigned int Y = (2*x+3*y)%5; x = y; y = Y;
                /* Swap current and state(x,y), and rotate */
                temp = readLane(x, y);
                writeLane(x, y, ROL64(current, r));
                current = temp;
            }
        }

        {   /* === xi step (see [Keccak Reference, Section 2.3.1]) === */
            keccak_lane_t temp[5];
            for(y=0; y<5; y++)
            {
                /* Take a copy of the plane */
                for(x=0; x<5; x++)
                    temp[x] = readLane(x, y);
                /* Compute xi on the plane */
                for(x=0; x<5; x++)
                    writeLane(x, y, temp[x] ^((~temp[(x+1)%5]) & temp[(x+2)%5]));
            }
        }

        {   /* === iota step (see [Keccak Reference, Section 2.3.5]) === */
            for(j=0; j<7; j++)
            {
                unsigned int bitPosition = (1<<j)-1; /* 2^j-1 */
                if (LFSR86540(&LFSRstate))
                    XORLane(0, 0, (keccak_lane_t)1<<bitPosition);
            }
        }
    }
}

void crypto_keccak_init(keccak_hasher_t* hasher, size_t mdlen, uint8_t delim)
{
    hasher->rate   = 200 - 2 * mdlen / 8;
    hasher->delim  = delim;
    hasher->offset = 0;
    os_memset(hasher->state.b, 0, sizeof(hasher->state.b));
}

void crypto_keccak_update(keccak_hasher_t* hasher, const void* vin, size_t inlen)
{
    const uint8_t* in = vin;
    size_t rsiz      = hasher->rate - hasher->offset;
    size_t offset    = hasher->offset;
    uint8_t* b = hasher->state.b;

    while (inlen >= rsiz)
    {
        for (size_t i = 0; i < rsiz; i++)
            b[offset + i] ^= in[i];
        KeccakF1600_StatePermute(b);
        inlen -= rsiz;
        in += rsiz;
        rsiz   = hasher->rate;
        offset = 0;
    }
    for (size_t i = 0; i < inlen; i++)
        b[offset + i] ^= in[i];
    hasher->offset = offset + inlen;
}

void crypto_keccak_final(keccak_hasher_t* hasher, uint8_t* out, size_t outlen)
{
    uint8_t* b = hasher->state.b;
    size_t rate      = hasher->rate;
    b[hasher->offset] ^= hasher->delim;
    b[rate - 1] ^= 0x80;

    KeccakF1600_StatePermute(b);

    for (; outlen >= rate; outlen -= rate, out += rate)
    {
        for (size_t i = 0; i < rate; i++)
            out[i] = b[i];
        KeccakF1600_StatePermute(b);
    }
    for (size_t i = 0; i < outlen; i++)
        out[i] = b[i];
}
