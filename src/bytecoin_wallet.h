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

#ifndef BYTECOIN_WALLET_H
#define BYTECOIN_WALLET_H

#include <stdbool.h>
#include "bytecoin_crypto.h"

typedef struct wallet_keys_s
{
    hash_t view_seed;
    hash_t wallet_key;
    secret_key_t view_secret_key;
    secret_key_t audit_key_base_secret_key;
    secret_key_t spend_secret_key;
    public_key_t sH;
    public_key_t A_plus_sH;
} wallet_keys_t;

void init_wallet_keys(wallet_keys_t* wallet_keys);

void get_wallet_keys(
        const wallet_keys_t* wallet_keys,
        hash_t* wallet_key,
        public_key_t* A_plus_sH,
        public_key_t* view_public_key,
        elliptic_curve_point_t* v_mul_A_plus_sH);

void scan_outputs(
        const wallet_keys_t* wallet_keys,
        const public_key_t* output_public_key,
        public_key_t* result);

void generate_keyimage_for_address(
        const wallet_keys_t* wallet_keys,
        const uint8_t* buf,
        size_t len,
        uint32_t address_index,
        keyimage_t* keyimage);

void generate_output_seed(
        const wallet_keys_t* wallet_keys,
        const hash_t* tx_inputs_hash,
        uint32_t out_index,
        hash_t* result);

void generate_sign_secret(
        const wallet_keys_t* wallet_keys,
        uint32_t i,
        const uint8_t secret_name[2],
        const hash_t* random_seed,
        secret_key_t* result);

void encrypt_scalar(
        const hash_t* encryption_key,
        const elliptic_curve_scalar_t* scalar,
        uint32_t i,
        const uint8_t scalar_name[2],
        hash_t* result);

void generate_random_keys(
        hash_t* random_seed,
        hash_t* encryption_key);

void prepare_address_secret(
        const wallet_keys_t* wallet_keys,
        uint32_t address_index,
        secret_key_t* result);

void prepare_address_public(
        const wallet_keys_t* wallet_keys,
        uint32_t address_index,
        public_key_t* address_S,
        public_key_t* address_Sv);

void export_view_only(
        const wallet_keys_t* wallet_keys,
        secret_key_t* audit_key_base_secret_key,
        secret_key_t* view_secret_key,
        hash_t* view_only,
        bool view_outgoing_addresses,
        signature_t* view_secrets_signature);

#endif // BYTECOIN_WALLET_H
