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

#ifndef BYTECOIN_SIG_H
#define BYTECOIN_SIG_H

#include <stdint.h>
#include <stdbool.h>
#include "bytecoin_wallet.h"
#include "bytecoin_crypto.h"

typedef enum bytecoin_signature_status_e
{
    SIG_STATE_FINISHED = 0,
    SIG_STATE_EXPECT_INPUT_START,
    SIG_STATE_EXPECT_INPUT_INDEXES,
    SIG_STATE_EXPECT_INPUT_FINISH,
    SIG_STATE_EXPECT_OUTPUT,
    SIG_STATE_EXPECT_USER_CONFIRMATION,
    SIG_STATE_EXPECT_EXTRA_CHUNK,
    SIG_STATE_EXPECT_STEP_A,
    SIG_STATE_EXPECT_STEP_A_MORE_DATA,
    SIG_STATE_EXPECT_STEP_B,
} bytecoin_signature_status_t;

typedef struct bytecoin_signing_state_s
{
    keccak_hasher_t tx_inputs_hasher;
    keccak_hasher_t tx_prefix_hasher;

    public_key_t dst_address_s;
    public_key_t dst_address_s_v;

    hash_t random_seed;
    hash_t tx_inputs_hash;
    hash_t encryption_key;
    hash_t step_args_hash;

    elliptic_curve_scalar_t c0;

    uint64_t inputs_amount;
    uint64_t dst_amount;
    uint64_t change_amount;
    uint64_t dst_fee;

    uint32_t extra_size;
    uint16_t inputs_num;
    uint16_t outputs_num;
    uint16_t mixin_num;

    uint16_t inputs_counter;
    uint16_t outputs_counter;
    uint16_t extra_counter;
    uint16_t mixin_counter;

    bool dst_address_set;

    uint8_t dst_address_tag;

    bytecoin_signature_status_t status;
} bytecoin_signing_state_t;

void init_signing_state(bytecoin_signing_state_t* sig_state);

void sig_start(
        bytecoin_signing_state_t* sig_state,
        uint32_t version,
        uint64_t ut,
        uint32_t inputs_num,
        uint32_t outputs_num,
        uint32_t extra_num);

void sig_add_input_start(
        bytecoin_signing_state_t* sig_state,
        uint64_t amount,
        uint32_t output_indexes_count);

void sig_add_input_indexes(
        bytecoin_signing_state_t* sig_state,
        const uint32_t* output_indexes,
        uint32_t output_indexes_length);

void sig_add_input_finish(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        const uint8_t* output_secret_hash_arg,
        uint32_t output_secret_hash_arg_len,
        uint32_t address_index);

int sig_add_output(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        bool change,
        uint64_t amount,
        uint32_t change_address_index,
        uint8_t dst_address_tag,
        const public_key_t* dst_address_s,
        const public_key_t* dst_address_s_v,
        public_key_t* public_key,
        public_key_t* encrypted_secret,
        uint8_t* encrypted_address_type);

void sig_add_output_final(bytecoin_signing_state_t* sig_state);

void sig_add_extra(
        bytecoin_signing_state_t* sig_state,
        const void* buf,
        uint32_t len);

void sig_step_a(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        const uint8_t* output_secret_hash_arg,
        uint32_t output_secret_hash_arg_len,
        uint32_t address_index,
        elliptic_curve_point_t* sig_p,
        elliptic_curve_point_t* y,
        elliptic_curve_point_t* z);

void sig_step_a_more_data(
        bytecoin_signing_state_t* sig_state,
        const void* buf,
        uint32_t len);

void sig_get_c0(
        bytecoin_signing_state_t* sig_state,
        elliptic_curve_scalar_t* c0);

void sig_step_b(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        const uint8_t* output_secret_hash_arg,
        uint32_t output_secret_hash_arg_len,
        uint32_t address_index,
        const elliptic_curve_scalar_t* my_c,
        hash_t* sig_my_rr,
        hash_t* sig_rs,
        hash_t* sig_ra,
        hash_t* e_key);

void sig_proof_start(
        bytecoin_signing_state_t* sig_state,
        uint32_t len);

#endif // BYTECOIN_SIG_H
