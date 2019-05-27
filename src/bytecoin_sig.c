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
#include "bytecoin_sig.h"
#include "bytecoin_ledger_api.h"
#include "bytecoin_wallet.h"
#include "bytecoin_keys.h"
#include "bytecoin_ui.h"
#include "bytecoin_debug.h"

#define BYTECOIN_INPUT_KEY_TAG  2
#define BYTECOIN_OUTPUT_KEY_TAG 2

#define BYTECOIN_SIMPLE_ADDRESS_TAG     0
#define BYTECOIN_UNLINKABLE_ADDRESS_TAG 1

static const uint8_t ka_str[] = { 'k', 'a' };
static const uint8_t ks_str[] = { 'k', 's' };
static const uint8_t kr_str[] = { 'k', 'r' };

static const uint8_t ra_str[] = { 'r', 'a' };
static const uint8_t rs_str[] = { 'r', 's' };
static const uint8_t rr_str[] = { 'r', 'r' };

void init_signing_state(bytecoin_signing_state_t* sig_state)
{
    os_memset(sig_state, 0, sizeof(bytecoin_signing_state_t));
    sig_state->status = SIG_STATE_FINISHED;
    sig_state->dst_address_set = false;
}

static
bool add_amount(uint64_t* sum, uint64_t amount)
{
    if (UINT64_MAX - amount < *sum)
        return false;
    *sum += amount;
    return true;
}

void sig_start(
        bytecoin_signing_state_t* sig_state,
        uint32_t version,
        uint64_t ut,
        uint32_t inputs_num,
        uint32_t outputs_num,
        uint32_t extra_num)
{
    if (inputs_num == 0 || outputs_num == 0 || version == 0)
    {
        THROW(SW_WRONG_DATA);
        return;
    }

    init_signing_state(sig_state);

    sig_state->inputs_num = inputs_num;
    sig_state->outputs_num = outputs_num;
    sig_state->extra_size = extra_num;

    keccak_init(&sig_state->tx_prefix_hasher);
    keccak_init(&sig_state->tx_inputs_hasher);

    // tx_prefix_hasher
    keccak_update_varint(&sig_state->tx_prefix_hasher, version);
    keccak_update_varint(&sig_state->tx_prefix_hasher, ut);
    keccak_update_varint(&sig_state->tx_prefix_hasher, inputs_num);

    // tx_inputs_hasher
    keccak_update_varint(&sig_state->tx_inputs_hasher, inputs_num);

    sig_state->status = SIG_STATE_EXPECT_INPUT_START;
}

void sig_add_input_start(
        bytecoin_signing_state_t* sig_state,
        uint64_t amount,
        uint32_t output_indexes_count)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_INPUT_START && sig_state->inputs_counter < sig_state->inputs_num);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }
    const bool is_amount_ok = add_amount(&sig_state->inputs_amount, amount);
    if (!is_amount_ok)
    {
        THROW(SW_WRONG_DATA);
        return;
    }

    // tx_prefix_hasher
    keccak_update_byte  (&sig_state->tx_prefix_hasher, BYTECOIN_INPUT_KEY_TAG);
    keccak_update_varint(&sig_state->tx_prefix_hasher, amount);
    keccak_update_varint(&sig_state->tx_prefix_hasher, output_indexes_count);

    // tx_inputs_hasher
    keccak_update_byte  (&sig_state->tx_inputs_hasher, BYTECOIN_INPUT_KEY_TAG);
    keccak_update_varint(&sig_state->tx_inputs_hasher, amount);
    keccak_update_varint(&sig_state->tx_inputs_hasher, output_indexes_count);
    sig_state->mixin_counter = 0;
    sig_state->mixin_num = output_indexes_count;
    sig_state->status = SIG_STATE_EXPECT_INPUT_INDEXES;
}

void sig_add_input_indexes(
        bytecoin_signing_state_t* sig_state,
        const uint32_t* output_indexes,
        uint32_t output_indexes_length)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_INPUT_INDEXES && sig_state->mixin_counter + output_indexes_length <= sig_state->mixin_num);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }

    for (uint32_t j = 0; j != output_indexes_length; ++j)
    {
        keccak_update_varint(&sig_state->tx_prefix_hasher, output_indexes[j]);
        keccak_update_varint(&sig_state->tx_inputs_hasher, output_indexes[j]);
    }
    sig_state->mixin_counter += output_indexes_length;
    if (sig_state->mixin_counter < sig_state->mixin_num)
        return;
    sig_state->status = SIG_STATE_EXPECT_INPUT_FINISH;
}

void sig_add_input_finish(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        const uint8_t* output_secret_hash_arg,
        uint32_t output_secret_hash_arg_len,
        uint32_t address_index)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_INPUT_FINISH);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }

    keyimage_t keyimage;
    generate_keyimage_for_address(wallet_keys, output_secret_hash_arg, output_secret_hash_arg_len, address_index, &keyimage);

    keccak_update(&sig_state->tx_prefix_hasher, keyimage.data, sizeof(keyimage.data));
    keccak_update(&sig_state->tx_inputs_hasher, keyimage.data, sizeof(keyimage.data));

    if (++sig_state->inputs_counter < sig_state->inputs_num)
    {
        sig_state->status = SIG_STATE_EXPECT_INPUT_START;
        return;
    }

    keccak_final(&sig_state->tx_inputs_hasher, &sig_state->tx_inputs_hash);
    keccak_update_varint(&sig_state->tx_prefix_hasher, sig_state->outputs_num);

    sig_state->status = SIG_STATE_EXPECT_OUTPUT;
}

static
void add_output_or_change(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        uint64_t amount,
        uint8_t dst_address_tag,
        const public_key_t* dst_address_s,
        const public_key_t* dst_address_s_v,
        public_key_t* public_key,
        public_key_t* encrypted_secret,
        uint8_t* encrypted_address_type)
{
    secret_key_t output_secret_scalar;
    elliptic_curve_point_t output_secret_point;
    uint8_t output_secret_address_type;

    {
        hash_t output_seed;
        generate_output_seed(wallet_keys, &sig_state->tx_inputs_hash, sig_state->outputs_counter, &output_seed);
        generate_output_secrets(&output_seed, &output_secret_scalar, &output_secret_point, &output_secret_address_type);
    }

    *encrypted_address_type = dst_address_tag ^ output_secret_address_type;

    const bool is_linkable = (dst_address_tag == BYTECOIN_SIMPLE_ADDRESS_TAG);
    is_linkable ?
            linkable_derive_output_public_key(
                &output_secret_scalar,
                &sig_state->tx_inputs_hash,
                sig_state->outputs_counter,
                dst_address_s,
                dst_address_s_v,
                public_key,
                encrypted_secret) :
            unlinkable_derive_output_public_key(
                &output_secret_point,
                &sig_state->tx_inputs_hash,
                sig_state->outputs_counter,
                dst_address_s,
                dst_address_s_v,
                public_key,
                encrypted_secret);

    const uint8_t output_tag = BYTECOIN_OUTPUT_KEY_TAG;
    keccak_update_byte  (&sig_state->tx_prefix_hasher, output_tag);
    keccak_update_varint(&sig_state->tx_prefix_hasher, amount);
    keccak_update       (&sig_state->tx_prefix_hasher, public_key->data, sizeof(public_key->data));
    keccak_update       (&sig_state->tx_prefix_hasher, encrypted_secret->data, sizeof(encrypted_secret->data));
    keccak_update_byte  (&sig_state->tx_prefix_hasher, *encrypted_address_type);
}

static
void add_change_output(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        uint64_t amount,
        uint32_t change_address_index,
        public_key_t* public_key,
        public_key_t* encrypted_secret,
        uint8_t* encrypted_address_type)
{
    const bool is_amount_ok = add_amount(&sig_state->change_amount, amount);
    if (!is_amount_ok)
    {
        THROW(SW_WRONG_DATA);
        return;
    }
    public_key_t change_address_s;
    public_key_t change_address_s_v;
    prepare_address_public(wallet_keys, change_address_index, &change_address_s, &change_address_s_v);
    add_output_or_change(sig_state, wallet_keys, amount, BYTECOIN_UNLINKABLE_ADDRESS_TAG, &change_address_s, &change_address_s_v, public_key, encrypted_secret, encrypted_address_type);
}

static
void add_output(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        uint64_t amount,
        uint8_t dst_address_tag,
        const public_key_t* dst_address_s,
        const public_key_t* dst_address_s_v,
        public_key_t* public_key,
        public_key_t* encrypted_secret,
        uint8_t* encrypted_address_type)
{
    if (sig_state->dst_address_set)
    {
        const bool is_address_ok =
                (sig_state->dst_address_tag == dst_address_tag &&
                 !os_memcmp(sig_state->dst_address_s.data, dst_address_s->data, sizeof (dst_address_s->data)) &&
                 !os_memcmp(sig_state->dst_address_s_v.data, dst_address_s_v->data, sizeof (dst_address_s_v->data)));
        if (!is_address_ok)
        {
            THROW(SW_WRONG_DATA);
            return;
        }
    }
    else
    {
        sig_state->dst_address_set = true;
        sig_state->dst_address_tag = dst_address_tag;
        sig_state->dst_address_s = *dst_address_s;
        sig_state->dst_address_s_v = *dst_address_s_v;
    }
    const bool is_amount_ok = add_amount(&sig_state->dst_amount, amount);
    if (!is_amount_ok)
    {
        THROW(SW_WRONG_DATA);
        return;
    }
    add_output_or_change(sig_state, wallet_keys, amount, sig_state->dst_address_tag, &sig_state->dst_address_s, &sig_state->dst_address_s_v, public_key, encrypted_secret, encrypted_address_type);
}

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
        uint8_t* encrypted_address_type)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_OUTPUT && sig_state->outputs_counter < sig_state->outputs_num);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return SW_COMMAND_NOT_ALLOWED;
    }

    if (change)
        add_change_output(
                    sig_state,
                    wallet_keys,
                    amount,
                    change_address_index,
                    public_key,
                    encrypted_secret,
                    encrypted_address_type);
    else
        add_output(sig_state,
                   wallet_keys,
                   amount,
                   dst_address_tag,
                   dst_address_s,
                   dst_address_s_v,
                   public_key,
                   encrypted_secret,
                   encrypted_address_type);


    if (++sig_state->outputs_counter < sig_state->outputs_num)
        return SW_NO_ERROR;

    uint64_t outputs_amount = sig_state->dst_amount;
    const bool is_outputs_amount_ok = add_amount(&outputs_amount, sig_state->change_amount);
    if (!is_outputs_amount_ok)
    {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
    }
    const bool is_inputs_amount_ok = (sig_state->inputs_amount >= outputs_amount);
    if (!is_inputs_amount_ok)
    {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
    }
    const uint64_t fee = sig_state->inputs_amount - outputs_amount;
    keccak_update_varint(&sig_state->tx_prefix_hasher, sig_state->extra_size);

    sig_state->status = SIG_STATE_EXPECT_USER_CONFIRMATION;
    sig_state->dst_fee = fee;
    return user_confirm_tx();

//    sig_add_output_final(sig_state); // DEBUG: bypass the confirmation
//    return SW_NO_ERROR;
}

void sig_add_output_final(bytecoin_signing_state_t* sig_state)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_USER_CONFIRMATION && sig_state->outputs_counter == sig_state->outputs_num);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }
    sig_state->status = SIG_STATE_EXPECT_EXTRA_CHUNK;
}

void sig_add_extra(
        bytecoin_signing_state_t* sig_state,
        const void* buf,
        uint32_t len)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_EXTRA_CHUNK && sig_state->extra_counter + len <= sig_state->extra_size);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }

    keccak_update(&sig_state->tx_prefix_hasher, buf, len);
    sig_state->extra_counter += len;
    if (sig_state->extra_counter < sig_state->extra_size)
        return;

    hash_t tx_prefix_hash;
    keccak_final(&sig_state->tx_prefix_hasher, &tx_prefix_hash);
    sig_state->inputs_counter = 0;

    keccak_init(&sig_state->tx_inputs_hasher);
    keccak_init(&sig_state->tx_prefix_hasher);
    keccak_update(&sig_state->tx_inputs_hasher, tx_prefix_hash.data, sizeof(tx_prefix_hash.data));

    generate_random_keys(&sig_state->random_seed, &sig_state->encryption_key);

    sig_state->status = SIG_STATE_EXPECT_STEP_A;
}

static
void calc_sig_p(
        const elliptic_curve_point_t* b_coin,
        const secret_key_t* output_secret_key_a,
        const secret_key_t* output_secret_key_s,
        elliptic_curve_point_t* sig_p)
{
    elliptic_curve_point_t p1_sub;
    elliptic_curve_point_t p2_sub;
    ecmul_H(output_secret_key_s, &p1_sub);
    ecmul(b_coin, output_secret_key_a, &p2_sub);
    ecsub(&p1_sub, &p2_sub, sig_p);
}

static
void calc_x(
        const bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        const elliptic_curve_point_t* b_coin,
        public_key_t* x)
{
    secret_key_t ks;
    secret_key_t ka;
    generate_sign_secret(wallet_keys, sig_state->inputs_counter, ks_str, &sig_state->random_seed, &ks);
    generate_sign_secret(wallet_keys, sig_state->inputs_counter, ka_str, &sig_state->random_seed, &ka);

    elliptic_curve_point_t p1_add;
    elliptic_curve_point_t p2_add;
    ecmul_H(&ks, &p1_add);
    ecmul(b_coin, &ka, &p2_add);
    ecadd(&p1_add, &p2_add, x); // x = ks * H + ka * b_coin
}

static
void calc_yz(
        const bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        const public_key_t* output_public_key,
        const elliptic_curve_point_t* b_coin,
        elliptic_curve_point_t* y,
        elliptic_curve_point_t* z)
{
    secret_key_t kr;
    generate_sign_secret(wallet_keys, sig_state->inputs_counter, kr_str, &sig_state->random_seed, &kr);

    {
        elliptic_curve_point_t G_plus_B;
        ecadd_G(b_coin, &G_plus_B);
        ecmul(&G_plus_B, &kr, y);
    }
    elliptic_curve_point_t hash_pubs_sec;
    hash_point_to_good_point(output_public_key, &hash_pubs_sec);
    ecmul(&hash_pubs_sec, &kr, z);
}

void sig_step_a(
        bytecoin_signing_state_t* sig_state,
        const wallet_keys_t* wallet_keys,
        const uint8_t* output_secret_hash_arg,
        uint32_t output_secret_hash_arg_len,
        uint32_t address_index,
        elliptic_curve_point_t* sig_p,
        elliptic_curve_point_t* y,
        elliptic_curve_point_t* z)
{
    if (sig_state->status == SIG_STATE_EXPECT_STEP_A_MORE_DATA && sig_state->inputs_counter + 1 < sig_state->inputs_num)
    {
        sig_state->inputs_counter += 1;
        sig_state->status = SIG_STATE_EXPECT_STEP_A;
    }

    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_STEP_A && sig_state->inputs_counter < sig_state->inputs_num);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }

    secret_key_t inv_output_secret_hash;
    {
        elliptic_curve_scalar_t output_secret_hash;
        hash_to_scalar(output_secret_hash_arg, output_secret_hash_arg_len, &output_secret_hash);
        invert32(&output_secret_hash, &inv_output_secret_hash);
    }

    secret_key_t output_secret_key_a;
    {
        secret_key_t address_audit_secret_key;
        prepare_address_secret(wallet_keys, address_index, &address_audit_secret_key);
        ecmulm(&address_audit_secret_key, &inv_output_secret_hash, &output_secret_key_a);
    }
    secret_key_t output_secret_key_s;
    ecmulm(&wallet_keys->spend_secret_key, &inv_output_secret_hash, &output_secret_key_s);
    public_key_t output_public_key;
    secret_keys_to_public_key(&output_secret_key_a, &output_secret_key_s, &output_public_key);
    keyimage_t keyimage;
    generate_keyimage(&output_public_key, &output_secret_key_a, &keyimage);

    keccak_update(&sig_state->tx_prefix_hasher, inv_output_secret_hash.data, sizeof(inv_output_secret_hash.data));
    keccak_update_varint(&sig_state->tx_prefix_hasher, address_index);

    elliptic_curve_point_t b_coin;
    hash_point_to_good_point(&keyimage, &b_coin);

    calc_sig_p(&b_coin, &output_secret_key_a, &output_secret_key_s, sig_p);
    keccak_update(&sig_state->tx_inputs_hasher, sig_p->data, sizeof(sig_p->data));

    {
        public_key_t x;
        calc_x(sig_state, wallet_keys, &b_coin, &x);
        keccak_update(&sig_state->tx_inputs_hasher, x.data, sizeof(x.data));
    }

    calc_yz(sig_state, wallet_keys, &output_public_key, &b_coin, y, z);

    sig_state->status = SIG_STATE_EXPECT_STEP_A_MORE_DATA;
}

void sig_step_a_more_data(
        bytecoin_signing_state_t* sig_state,
        const void* buf,
        uint32_t len)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_STEP_A_MORE_DATA);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }

    keccak_update(&sig_state->tx_inputs_hasher, buf, len);
}

void sig_get_c0(
        bytecoin_signing_state_t* sig_state,
        elliptic_curve_scalar_t* result)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_STEP_A_MORE_DATA && sig_state->inputs_counter + 1 == sig_state->inputs_num);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }

    keccak_final_to_scalar(&sig_state->tx_inputs_hasher, &sig_state->c0);
    PRINT_PRIMITIVE(sig_state->c0);
    sig_state->inputs_counter = 0;
    keccak_final(&sig_state->tx_prefix_hasher, &sig_state->step_args_hash);
    keccak_init(&sig_state->tx_prefix_hasher);
    os_memmove(result->data, sig_state->c0.data, sizeof(result->data));
    sig_state->status = SIG_STATE_EXPECT_STEP_B;
}

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
        hash_t* e_key)
{
    const bool call_is_expected = (sig_state->status == SIG_STATE_EXPECT_STEP_B && sig_state->inputs_counter < sig_state->inputs_num);
    if (!call_is_expected)
    {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return;
    }

    secret_key_t inv_output_secret_hash;
    {
        elliptic_curve_scalar_t output_secret_hash;
        hash_to_scalar(output_secret_hash_arg, output_secret_hash_arg_len, &output_secret_hash);
        invert32(&output_secret_hash, &inv_output_secret_hash);
    }

    secret_key_t output_secret_key_a;
    {
        secret_key_t address_audit_secret_key;
        prepare_address_secret(wallet_keys, address_index, &address_audit_secret_key);
        ecmulm(&address_audit_secret_key, &inv_output_secret_hash, &output_secret_key_a);
    }
    secret_key_t output_secret_key_s;
    ecmulm(&wallet_keys->spend_secret_key, &inv_output_secret_hash, &output_secret_key_s);

    keccak_update(&sig_state->tx_prefix_hasher, inv_output_secret_hash.data, sizeof(inv_output_secret_hash.data));
    keccak_update_varint(&sig_state->tx_prefix_hasher, address_index);

    {
        secret_key_t ks;
        generate_sign_secret(wallet_keys, sig_state->inputs_counter, ks_str, &sig_state->random_seed, &ks);
        elliptic_curve_scalar_t rs_sub;
        ecmulm(&sig_state->c0, &output_secret_key_s, &rs_sub);
        secret_key_t rsig_rs;
        ecsubm(&ks, &rs_sub, &rsig_rs);
        encrypt_scalar(&sig_state->encryption_key, &rsig_rs, sig_state->inputs_counter, rs_str, sig_rs);
    }
    {
        secret_key_t ka;
        generate_sign_secret(wallet_keys, sig_state->inputs_counter, ka_str, &sig_state->random_seed, &ka);
        elliptic_curve_scalar_t ra_add;
        ecmulm(&sig_state->c0, &output_secret_key_a, &ra_add);
        secret_key_t rsig_ra;
        ecaddm(&ka, &ra_add, &rsig_ra);
        encrypt_scalar(&sig_state->encryption_key, &rsig_ra, sig_state->inputs_counter, ra_str, sig_ra);
    }
    {
        secret_key_t kr;
        generate_sign_secret(wallet_keys, sig_state->inputs_counter, kr_str, &sig_state->random_seed, &kr);
        elliptic_curve_scalar_t rr_sub;
        ecmulm(my_c, &output_secret_key_a, &rr_sub);
        secret_key_t rsig_my_rr;
        ecsubm(&kr, &rr_sub, &rsig_my_rr);
        encrypt_scalar(&sig_state->encryption_key, &rsig_my_rr, sig_state->inputs_counter, rr_str, sig_my_rr);
    }

    if (++sig_state->inputs_counter < sig_state->inputs_num)
    {
        os_memset(e_key->data, 0, sizeof(e_key->data));
        return;
    }
    hash_t step_args_hash2;
    keccak_final(&sig_state->tx_prefix_hasher, &step_args_hash2);
    if (os_memcmp(sig_state->step_args_hash.data, step_args_hash2.data, sizeof(step_args_hash2.data)) != 0)
        os_memset(sig_state->encryption_key.data, 0, sizeof(sig_state->encryption_key.data));
    *e_key = sig_state->encryption_key;

    sig_state->status = SIG_STATE_FINISHED;
}

void sig_proof_start(
        bytecoin_signing_state_t* sig_state,
        uint32_t len)
{
    init_signing_state(sig_state);
    sig_state->inputs_num = 1;
    sig_state->extra_size = len;

    keccak_init(&sig_state->tx_prefix_hasher);
    keccak_update_byte(&sig_state->tx_prefix_hasher, 0);
    sig_state->status = SIG_STATE_EXPECT_EXTRA_CHUNK;
}


