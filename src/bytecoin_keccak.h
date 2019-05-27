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

#ifndef BYTECOIN_KECCAK_H
#define BYTECOIN_KECCAK_H

#include <stdint.h>
#include <stddef.h>

typedef struct keccak_state_s {
    uint8_t b[200];
} keccak_state_t;

typedef struct keccak_hasher_s {
    keccak_state_t state;
    size_t offset;
    size_t rate;
    uint8_t delim;
} keccak_hasher_t;

void crypto_keccak_init(keccak_hasher_t* hasher, size_t mdlen, uint8_t delim);
void crypto_keccak_update(keccak_hasher_t* hasher, const void* vin, size_t inlen);
void crypto_keccak_final(keccak_hasher_t* hasher, uint8_t* out, size_t outlen);


#endif // BYTECOIN_KECCAK_H
