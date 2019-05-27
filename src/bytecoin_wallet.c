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
#include "bytecoin_wallet.h"
#include "bytecoin_keys.h"
#include "bytecoin_debug.h"

// m/44'/204'/1'/0/0
static const uint32_t  path[] = {
    0x8000002C,
    0x800000CC,
    0x80000001, // address type
    0x00000000,
    0x00000000
};

static const char view_seed_str[]      = "view_seed";
static const char view_key_str[]       = "view_key";
static const char view_key_audit_str[] = "view_key_audit";
static const char spend_key_str[]      = "spend_key";
static const char wallet_key_str[]     = "wallet_key";

#ifdef BYTECOIN_DEBUG_SEED
static const char bcn_str[] = "bcn";
#endif

uint32_t G_last_index;
uint8_t G_last_audit_secret_key[sizeof(secret_key_t)];

void init_wallet_keys(wallet_keys_t* wallet_keys)
{
    uint8_t bpk[32];
    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, path, sizeof(path) / sizeof(path[0]), bpk, NULL);
    hash_t seed;
    fast_hash(bpk, sizeof(bpk), &seed);

    derive_from_seed_to_hash  (&seed, view_seed_str,  sizeof(view_seed_str)  - 1, &wallet_keys->view_seed);
    derive_from_seed_to_hash  (&seed, wallet_key_str, sizeof(wallet_key_str) - 1, &wallet_keys->wallet_key);
    derive_from_seed_to_scalar(&seed, spend_key_str,  sizeof(spend_key_str)  - 1, &wallet_keys->spend_secret_key);
    derive_from_seed_to_scalar(&wallet_keys->view_seed, view_key_str,       sizeof(view_key_str)       - 1, &wallet_keys->view_secret_key);
    derive_from_seed_to_scalar(&wallet_keys->view_seed, view_key_audit_str, sizeof(view_key_audit_str) - 1, &wallet_keys->audit_key_base_secret_key);

    PRINT_PRIMITIVE(wallet_keys->audit_key_base_secret_key);
    secret_keys_to_A_plus_sH(
                &wallet_keys->spend_secret_key,
                &wallet_keys->audit_key_base_secret_key,
                &wallet_keys->sH,
                &wallet_keys->A_plus_sH);

    G_last_index = UINT32_MAX;
    os_memset(G_last_audit_secret_key, 0, sizeof(G_last_audit_secret_key));
}

void prepare_address_secret(
        const wallet_keys_t* wallet_keys,
        uint32_t address_index,
        secret_key_t* result)
{
    if (G_last_index != address_index)
    {
        generate_hd_secret_key(&wallet_keys->audit_key_base_secret_key, &wallet_keys->A_plus_sH, address_index, (secret_key_t*)G_last_audit_secret_key);
        G_last_index = address_index;
    }
    os_memmove(result->data, G_last_audit_secret_key, sizeof(result->data));
}

void prepare_address_public(
        const wallet_keys_t* wallet_keys,
        uint32_t address_index,
        public_key_t* address_S,
        public_key_t* address_Sv)
{
    secret_key_t address_audit_secret_key;
    prepare_address_secret(wallet_keys, address_index, &address_audit_secret_key);
    public_key_t address_audit_public_key;
    secret_key_to_public_key(&address_audit_secret_key, &address_audit_public_key);

    ecadd(&address_audit_public_key, &wallet_keys->sH, address_S);
    ecmul(address_S, &wallet_keys->view_secret_key, address_Sv);
}

static inline
void unlinkable_underive_address_S_step1(
        const secret_key_t* view_secret_key,
        const public_key_t* output_public_key,
        public_key_t* result)
{
    ecmul(output_public_key, view_secret_key, result);
}

void get_wallet_keys(
        const wallet_keys_t* wallet_keys,
        hash_t* wallet_key,
        public_key_t* A_plus_sH,
        public_key_t* view_public_key,
        elliptic_curve_point_t* v_mul_A_plus_sH)
{
    *wallet_key = wallet_keys->wallet_key;
    *A_plus_sH = wallet_keys->A_plus_sH;
    secret_key_to_public_key(&wallet_keys->view_secret_key, view_public_key);
    ecmul(&wallet_keys->A_plus_sH, &wallet_keys->view_secret_key, v_mul_A_plus_sH);
}

void scan_outputs(
        const wallet_keys_t* wallet_keys,
        const public_key_t* output_public_key,
        public_key_t* result)
{
    unlinkable_underive_address_S_step1(&wallet_keys->view_secret_key, output_public_key, result);
}

void generate_keyimage_for_address(
        const wallet_keys_t* wallet_keys,
        const uint8_t* buf,
        size_t len,
        uint32_t address_index,
        keyimage_t* keyimage)
{
    elliptic_curve_scalar_t output_secret_hash;
    hash_to_scalar(buf, len, &output_secret_hash);
    secret_key_t inv_output_secret_hash;
    invert32(&output_secret_hash, &inv_output_secret_hash);

    secret_key_t address_audit_secret_key;
    prepare_address_secret(wallet_keys, address_index, &address_audit_secret_key);
    secret_key_t output_secret_key_a;
    ecmulm(&address_audit_secret_key, &inv_output_secret_hash, &output_secret_key_a);
    secret_key_t output_secret_key_s;
    ecmulm(&wallet_keys->spend_secret_key, &inv_output_secret_hash, &output_secret_key_s);
    public_key_t output_public_key;
    secret_keys_to_public_key(&output_secret_key_a, &output_secret_key_s, &output_public_key);
    generate_keyimage(&output_public_key, &output_secret_key_a, keyimage);
}

void generate_output_seed(
        const wallet_keys_t* wallet_keys,
        const hash_t* tx_inputs_hash,
        uint32_t out_index,
        hash_t* result)
{
    keccak_hasher_t hasher;
    keccak_init(&hasher);
    keccak_update(&hasher, wallet_keys->view_seed.data, sizeof(wallet_keys->view_seed.data));
    keccak_update(&hasher, tx_inputs_hash->data, sizeof(tx_inputs_hash->data));
    keccak_update_varint(&hasher, out_index);
    keccak_final(&hasher, result);
}

void generate_sign_secret(
        const wallet_keys_t* wallet_keys,
        uint32_t i,
        const uint8_t secret_name[2],
        const hash_t* random_seed,
        secret_key_t* result)
{
    keccak_hasher_t hasher;
    keccak_init(&hasher);
    keccak_update(&hasher, random_seed->data, sizeof(random_seed->data));

    uint8_t reversed[sizeof(wallet_keys->spend_secret_key.data)];
    reverse(reversed, wallet_keys->spend_secret_key.data, sizeof(reversed));

    keccak_update(&hasher, reversed, sizeof(reversed));
    keccak_update_byte(&hasher, secret_name[0]);
    keccak_update_byte(&hasher, secret_name[1]);
    keccak_update_varint(&hasher, i);
    keccak_final_to_scalar64(&hasher, result);
}

void encrypt_scalar(
        const hash_t* encryption_key,
        const elliptic_curve_scalar_t* scalar,
        uint32_t i,
        const uint8_t scalar_name[2],
        hash_t* result)
{
    {
        keccak_hasher_t hasher;
        keccak_init(&hasher);
        keccak_update(&hasher, encryption_key->data, sizeof(encryption_key->data));
        keccak_update_byte(&hasher, scalar_name[0]);
        keccak_update_byte(&hasher, scalar_name[1]);
        keccak_update_varint(&hasher, i);
        keccak_final(&hasher, result);
    }
    for (uint32_t j = 0; j < sizeof(scalar->data); ++j)
        result->data[j] ^= scalar->data[sizeof(scalar->data) - j - 1];
}

void generate_random_keys(
        hash_t* random_seed,
        hash_t* encryption_key)
{
#ifdef BYTECOIN_DEBUG_SEED
    fast_hash(bcn_str, sizeof(bcn_str) - 1, random_seed);
    fast_hash(bcn_str, sizeof(bcn_str) - 1, encryption_key);
#else
    generate_random_bytes(random_seed->data,    sizeof(random_seed->data));
    generate_random_bytes(encryption_key->data, sizeof(encryption_key->data));
#endif
}

void export_view_only(
        const wallet_keys_t* wallet_keys,
        secret_key_t* audit_key_base_secret_key,
        secret_key_t* view_secret_key,
        hash_t* view_seed,
        bool view_outgoing_addresses,
        signature_t* view_secrets_signature)
{
    *view_secret_key = wallet_keys->view_secret_key;
    *audit_key_base_secret_key = wallet_keys->audit_key_base_secret_key;

    if (view_outgoing_addresses)
        *view_seed = wallet_keys->view_seed;
    else
        os_memset(view_seed->data, 0, sizeof(view_seed->data));

    generate_proof_H(&wallet_keys->spend_secret_key, view_secrets_signature);
}

