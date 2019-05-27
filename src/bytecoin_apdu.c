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

#include "bytecoin_apdu.h"
#include "bytecoin_ledger_api.h"
#include "bytecoin_io.h"
#include "bytecoin_vars.h"
#include "bytecoin_debug.h"

int bytecoin_apdu_get_ledger_app_info(void)
{
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    const uint8_t major_version = BYTECOIN_VERSION_M;
    const uint8_t minor_version = BYTECOIN_VERSION_N;
    const uint8_t patch_version = BYTECOIN_VERSION_P;

    insert_var(major_version);
    insert_var(minor_version);
    insert_var(patch_version);

    const uint8_t app_name_size = sizeof(XSTR(BYTECOIN_NAME)) - 1;
    insert_var(app_name_size);
    insert_bytes_to_io_buffer(&G_bytecoin_vstate.io_buffer, XSTR(BYTECOIN_NAME), app_name_size);
    const uint8_t app_version_size = sizeof(XSTR(BYTECOIN_VERSION)) - 1;
    insert_var(app_version_size);
    insert_bytes_to_io_buffer(&G_bytecoin_vstate.io_buffer, XSTR(BYTECOIN_VERSION), app_version_size);
    const uint8_t app_specversion_size = sizeof(XSTR(BYTECOIN_SPEC_VERSION)) - 1;
    insert_var(app_specversion_size);
    insert_bytes_to_io_buffer(&G_bytecoin_vstate.io_buffer, XSTR(BYTECOIN_SPEC_VERSION), app_specversion_size);

    return SW_NO_ERROR;
}

int bytecoin_apdu_get_wallet_keys(void)
{
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    hash_t wallet_key;
    public_key_t A_plus_sH;
    public_key_t view_public_key;
    elliptic_curve_point_t v_mul_A_plus_sH;


    get_wallet_keys(&G_bytecoin_vstate.wallet_keys, &wallet_key, &A_plus_sH, &view_public_key, &v_mul_A_plus_sH);

    insert_hash      (wallet_key);
    insert_public_key(A_plus_sH);
    insert_point     (v_mul_A_plus_sH);
    insert_public_key(view_public_key);

    return SW_NO_ERROR;
}

int bytecoin_apdu_scan_outputs(void)
{
    const uint8_t len = fetch_var(uint8_t);
    if (len > BYTECOIN_MAX_SCAN_OUTPUTS)
        THROW(SW_NOT_ENOUGH_MEMORY);

    public_key_t output_public_keys[BYTECOIN_MAX_SCAN_OUTPUTS];
    for (uint8_t i = 0; i < len; ++i)
        output_public_keys[i] = fetch_public_key();
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    for (uint8_t i = 0; i < len; ++i)
    {
        public_key_t result;
        scan_outputs(&G_bytecoin_vstate.wallet_keys, &output_public_keys[i], &result);
        insert_public_key(result);
    }
    return SW_NO_ERROR;
}

int bytecoin_apdu_generate_keyimage(void)
{
    const uint8_t len = fetch_var(uint8_t);
    if (len > BYTECOIN_MAX_BUFFER_SIZE)
        THROW(SW_NOT_ENOUGH_MEMORY);
    uint8_t output_secret_hash_arg[BYTECOIN_MAX_BUFFER_SIZE];
    fetch_bytes_from_io_buffer(&G_bytecoin_vstate.io_buffer, output_secret_hash_arg, len);
    const uint32_t address_index = fetch_var(uint32_t);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    keyimage_t result;

    generate_keyimage_for_address(&G_bytecoin_vstate.wallet_keys, output_secret_hash_arg, len, address_index, &result);

    insert_keyimage(result);

    return SW_NO_ERROR;
}

int bytecoin_apdu_generate_output_seed(void)
{
    const hash_t tx_inputs_hash = fetch_hash();
    const uint32_t out_index    = fetch_var(uint32_t);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    hash_t result;
    generate_output_seed(&G_bytecoin_vstate.wallet_keys, &tx_inputs_hash, out_index, &result);

    insert_hash(result);
    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_start(void)
{
    const uint32_t version     = fetch_var(uint32_t);
    const uint64_t ut          = fetch_var(uint64_t);
    const uint32_t inputs_num  = fetch_var(uint32_t);
    const uint32_t outputs_num = fetch_var(uint32_t);
    const uint32_t extra_num   = fetch_var(uint32_t);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    sig_start(&G_bytecoin_vstate.sig_state, version, ut, inputs_num, outputs_num, extra_num);

    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_add_input_start(void)
{
    const uint64_t amount = fetch_var(uint64_t);
    const uint32_t output_indexes_count   = fetch_var(uint32_t);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    sig_add_input_start(&G_bytecoin_vstate.sig_state, amount, output_indexes_count);

    return SW_NO_ERROR;

}

int bytecoin_apdu_sig_add_input_indexes(void)
{
    const uint8_t output_indexes_len = fetch_var(uint8_t);
    if (output_indexes_len > BYTECOIN_MAX_OUTPUT_INDEXES)
        THROW(SW_NOT_ENOUGH_MEMORY);
    uint32_t output_indexes[BYTECOIN_MAX_OUTPUT_INDEXES];
    for (uint32_t i = 0; i < output_indexes_len; ++i)
        output_indexes[i] = fetch_var_from_io_buffer(&G_bytecoin_vstate.io_buffer, sizeof(output_indexes[0]));
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    sig_add_input_indexes(&G_bytecoin_vstate.sig_state, output_indexes, output_indexes_len);

    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_add_input_finish(void)
{
    const uint8_t len = fetch_var(uint8_t);
    if (len > BYTECOIN_MAX_BUFFER_SIZE)
        THROW(SW_NOT_ENOUGH_MEMORY);
    uint8_t output_secret_hash_arg[BYTECOIN_MAX_BUFFER_SIZE];
    fetch_bytes_from_io_buffer(&G_bytecoin_vstate.io_buffer, output_secret_hash_arg, len);
    const uint32_t address_index = fetch_var(uint32_t);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    sig_add_input_finish(&G_bytecoin_vstate.sig_state, &G_bytecoin_vstate.wallet_keys, output_secret_hash_arg, len, address_index);

    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_add_output(void)
{
    const uint8_t change                = fetch_var(uint8_t);
    const uint64_t amount               = fetch_var(uint64_t);
    const uint32_t change_address_index = fetch_var(uint32_t);
    const uint8_t dst_address_tag       = fetch_var(uint8_t);
    const public_key_t dst_address_s    = fetch_public_key();
    const public_key_t dst_address_s_v  = fetch_public_key();
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    public_key_t public_key;
    public_key_t encrypted_secret;
    uint8_t encrypted_address_type;

    const int rc = sig_add_output(
                &G_bytecoin_vstate.sig_state,
                &G_bytecoin_vstate.wallet_keys,
                change ? true : false,
                amount,
                change_address_index,
                dst_address_tag,
                &dst_address_s,
                &dst_address_s_v,
                &public_key,
                &encrypted_secret,
                &encrypted_address_type);

    insert_public_key(public_key);
    insert_public_key(encrypted_secret);
    insert_var       (encrypted_address_type);

    return rc;
}

int bytecoin_apdu_sig_add_output_final(void)
{
    sig_add_output_final(&G_bytecoin_vstate.sig_state);
    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_add_extra(void)
{
    const uint8_t len = fetch_var(uint8_t);

    if (len > BYTECOIN_MAX_BUFFER_SIZE)
        THROW(SW_NOT_ENOUGH_MEMORY);
    uint8_t buf[BYTECOIN_MAX_BUFFER_SIZE];
    fetch_bytes_from_io_buffer(&G_bytecoin_vstate.io_buffer, buf, len);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    sig_add_extra(&G_bytecoin_vstate.sig_state, buf, len);

    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_step_a(void)
{
    const uint8_t len = fetch_var(uint8_t);
    if (len > BYTECOIN_MAX_BUFFER_SIZE)
        THROW(SW_NOT_ENOUGH_MEMORY);
    uint8_t output_secret_hash_arg[BYTECOIN_MAX_BUFFER_SIZE];
    fetch_bytes_from_io_buffer(&G_bytecoin_vstate.io_buffer, output_secret_hash_arg, len);
    const uint32_t address_index = fetch_var(uint32_t);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    elliptic_curve_point_t sig_p;
    elliptic_curve_point_t y;
    elliptic_curve_point_t z;

    sig_step_a(&G_bytecoin_vstate.sig_state,
               &G_bytecoin_vstate.wallet_keys,
               output_secret_hash_arg,
               len,
               address_index,
               &sig_p,
               &y,
               &z);

    insert_point(sig_p);
    insert_point(y);
    insert_point(z);

    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_step_a_more_data(void)
{
    const uint8_t len = fetch_var(uint8_t);
    if (len > BYTECOIN_MAX_BUFFER_SIZE)
        THROW(SW_NOT_ENOUGH_MEMORY);
    uint8_t buf[BYTECOIN_MAX_BUFFER_SIZE];
    fetch_bytes_from_io_buffer(&G_bytecoin_vstate.io_buffer, buf, len);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    sig_step_a_more_data(&G_bytecoin_vstate.sig_state, buf, len);

    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_get_c0(void)
{
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    elliptic_curve_scalar_t c0;
    sig_get_c0(&G_bytecoin_vstate.sig_state, &c0);

    insert_scalar(c0);

    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_step_b(void)
{
    const uint8_t len = fetch_var(uint8_t);
    if (len > BYTECOIN_MAX_BUFFER_SIZE)
        THROW(SW_NOT_ENOUGH_MEMORY);
    uint8_t output_secret_hash_arg[BYTECOIN_MAX_BUFFER_SIZE];
    fetch_bytes_from_io_buffer(&G_bytecoin_vstate.io_buffer, output_secret_hash_arg, len);
    const uint32_t address_index = fetch_var(uint32_t);
    const elliptic_curve_scalar_t my_c = fetch_scalar();
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    hash_t sig_my_rr;
    hash_t sig_rs;
    hash_t sig_ra;
    hash_t e_key;

    sig_step_b(&G_bytecoin_vstate.sig_state,
               &G_bytecoin_vstate.wallet_keys,
               output_secret_hash_arg,
               len,
               address_index,
               &my_c,
               &sig_my_rr,
               &sig_rs,
               &sig_ra,
               &e_key);

    insert_hash(sig_my_rr);
    insert_hash(sig_rs);
    insert_hash(sig_ra);
    insert_hash(e_key);

    return SW_NO_ERROR;
}


int bytecoin_apdu_export_view_only(void)
{
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);
    return user_confirm_export_view_only();
}

int bytecoin_apdu_export_view_only_final(bool view_outgoing_addresses)
{
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    secret_key_t audit_key_base_secret_key;
    secret_key_t view_secret_key;
    hash_t tx_derivation_seed;
    signature_t view_secrets_signature;

    export_view_only(&G_bytecoin_vstate.wallet_keys,
                     &audit_key_base_secret_key,
                     &view_secret_key,
                     &tx_derivation_seed,
                     view_outgoing_addresses,
                     &view_secrets_signature);

    if (!view_outgoing_addresses)
        os_memset(tx_derivation_seed.data, 0, sizeof(tx_derivation_seed.data));

    insert_secret_key(audit_key_base_secret_key);
    insert_secret_key(view_secret_key);
    insert_hash      (tx_derivation_seed);
    insert_scalar    (view_secrets_signature.c);
    insert_scalar    (view_secrets_signature.r);

    return SW_NO_ERROR;
}

int bytecoin_apdu_sig_proof_start(void)
{
    const uint32_t len = fetch_var(uint32_t);
    reset_io_buffer(&G_bytecoin_vstate.io_buffer);

    sig_proof_start(&G_bytecoin_vstate.sig_state, len);

    return SW_NO_ERROR;
}
