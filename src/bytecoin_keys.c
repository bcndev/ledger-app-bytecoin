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
#include "bytecoin_keys.h"
#include "bytecoin_fe.h"
#include "bytecoin_ledger_api.h"
#include "bytecoin_base58.h"
#include "bytecoin_debug.h"

static const char address_str[] = "address";

void derive_from_seed_to_hash(const hash_t* seed, const void* buf, size_t len, hash_t* result)
{
    keccak_hasher_t hasher;
    keccak_init(&hasher);
    keccak_update(&hasher, seed->data, sizeof(seed->data));
    keccak_update(&hasher, buf, len);
    keccak_final(&hasher, result);
}

void derive_from_seed_to_scalar(const hash_t* seed, const void* buf, size_t len, elliptic_curve_scalar_t* result)
{
    hash_t hash;
    derive_from_seed_to_hash(seed, buf, len, &hash);
    reduce32(&hash, result);
}

void secret_key_to_public_key(const secret_key_t* secret_key, public_key_t* result)
{
    ecmul_G(secret_key, result);
}

void secret_keys_to_public_key(const secret_key_t* a, const secret_key_t* b, public_key_t* result)
{
    elliptic_curve_point_t gmul;
    elliptic_curve_point_t hmul;
    ecmul_G(a, &gmul);
    ecmul_H(b, &hmul);
    ecadd(&gmul, &hmul, result);
}

void secret_keys_to_A_plus_sH(
        const secret_key_t* spend_secret_key,
        const secret_key_t* audit_key_base_secret_key,
        public_key_t* sH,
        public_key_t* A_plus_sH)
{
    elliptic_curve_point_t A;
    ecmul_G(audit_key_base_secret_key, &A);
    ecmul_H(spend_secret_key, sH);
    ecadd(&A, sH, A_plus_sH);
}

void generate_keyimage(const public_key_t* pub, const secret_key_t* sec, keyimage_t* result)
{
    elliptic_curve_point_t pub_hash;
    hash_point_to_good_point(pub, &pub_hash);
    ecmul(&pub_hash, sec, result);
}

void generate_hd_secret_key(const secret_key_t* a0, const public_key_t* A_plus_sH, uint32_t index, secret_key_t* result)
{
    keccak_hasher_t hasher;
    keccak_init(&hasher);
    keccak_update(&hasher, A_plus_sH->data, sizeof(A_plus_sH->data));
    keccak_update(&hasher, address_str, sizeof(address_str) - 1);
    keccak_update_varint(&hasher, index);
    secret_key_t delta_secret_key;
    keccak_final_to_scalar(&hasher, &delta_secret_key);
    ecaddm(&delta_secret_key, a0, result);
}

void generate_output_secrets(const hash_t* output_seed, secret_key_t* output_secret_scalar, public_key_t* output_secret_point, uint8_t* output_secret_address_type)
{
    reduce32(output_seed, output_secret_scalar);

    ge_fromfe_frombytes(output_seed, output_secret_point);
    ecmul_8(output_secret_point, output_secret_point);

    hash_t output_secret_address_type_hash;
    fast_hash(output_seed->data, sizeof(output_seed->data), &output_secret_address_type_hash);

    *output_secret_address_type = output_secret_address_type_hash.data[0];
}

void linkable_derive_output_public_key(
        const secret_key_t* output_secret_scalar,
        const hash_t* tx_inputs_hash,
        uint32_t output_index,
        const public_key_t* address_s,
        const public_key_t* address_v,
        public_key_t* output_public_key,
        public_key_t* encrypted_output_secret)
{
    // TODO: check scalar

    ecmul(address_v, output_secret_scalar, encrypted_output_secret);

    elliptic_curve_point_t derivation;
    ecmul_G(output_secret_scalar, &derivation);

    elliptic_curve_scalar_t derivation_hash;
    {
        keccak_hasher_t hasher;
        keccak_init         (&hasher);
        keccak_update       (&hasher, derivation.data, sizeof(derivation.data));
        keccak_update       (&hasher, tx_inputs_hash->data, sizeof(tx_inputs_hash->data));
        keccak_update_varint(&hasher, output_index);
        keccak_final_to_scalar(&hasher, &derivation_hash);
    }

    elliptic_curve_point_t point3;
    ecmul_G(&derivation_hash, &point3);
    ecadd(address_s, &point3, output_public_key);
}

void unlinkable_derive_output_public_key(
        const elliptic_curve_point_t* output_secret_point,
        const hash_t* tx_inputs_hash,
        uint32_t output_index,
        const public_key_t* address_s,
        const public_key_t* address_s_v,
        public_key_t* output_public_key,
        public_key_t* encrypted_output_secret)
{
    secret_key_t spend_scalar;
    {
        keccak_hasher_t hasher;
        keccak_init         (&hasher);
        keccak_update       (&hasher, output_secret_point->data, sizeof(output_secret_point->data));
        keccak_update       (&hasher, tx_inputs_hash->data, sizeof(tx_inputs_hash->data));
        keccak_update_varint(&hasher, output_index);
        keccak_final_to_scalar(&hasher, &spend_scalar);
    }
    secret_key_t inv_spend_scalar;
    invert32(&spend_scalar, &inv_spend_scalar);
    ecmul(address_s, &inv_spend_scalar, output_public_key);

    elliptic_curve_point_t output_secret_add;
    ecmul(address_s_v, &inv_spend_scalar, &output_secret_add);
    ecadd(output_secret_point, &output_secret_add, encrypted_output_secret);
}

#define ADDR_CHECKSUM_SIZE       4

size_t encode_address(
        uint64_t prefix,
        const public_key_t* spend,
        const public_key_t* view,
        char* result,
        size_t result_len)
{
    uint8_t data[72];
    size_t size = encode_varint(prefix, data);
    if (size + sizeof(spend->data) + sizeof(view->data) + ADDR_CHECKSUM_SIZE > sizeof(data))
        THROW(SW_NOT_ENOUGH_MEMORY);
    os_memmove(data + size, spend->data, sizeof(spend->data));
    size += sizeof(spend->data);
    os_memmove(data + size, view->data, sizeof(view->data));
    size += sizeof(view->data);

    {
        hash_t hash;
        fast_hash(data, size, &hash);
        os_memmove(data + size, hash.data, ADDR_CHECKSUM_SIZE);
        size += ADDR_CHECKSUM_SIZE;
    }
    return encode_base58(data, size, result, result_len);
}

#define BYTECOIN_SHORTENED_ADDRESS_PART 7
#define BYTECOIN_SHORTENED_ADDRESS_DOTS 3

void short_address(char* addr_str, size_t size)
{
    os_memset(addr_str + BYTECOIN_SHORTENED_ADDRESS_PART, '.', BYTECOIN_SHORTENED_ADDRESS_DOTS);
    os_memmove(addr_str + BYTECOIN_SHORTENED_ADDRESS_PART + BYTECOIN_SHORTENED_ADDRESS_DOTS, addr_str + size - BYTECOIN_SHORTENED_ADDRESS_PART, BYTECOIN_SHORTENED_ADDRESS_PART);
    os_memset(addr_str + 2*BYTECOIN_SHORTENED_ADDRESS_PART + BYTECOIN_SHORTENED_ADDRESS_DOTS, 0, size - (2*BYTECOIN_SHORTENED_ADDRESS_PART - BYTECOIN_SHORTENED_ADDRESS_DOTS));
}

static
void random_scalar(elliptic_curve_scalar_t* result)
{
    hash_t h_result;
    generate_random_bytes(h_result.data, sizeof(h_result.data));
    reduce32(&h_result, result);
}

void generate_proof_H(const secret_key_t* s, signature_t* result)
{
    elliptic_curve_scalar_t k;
    random_scalar(&k);
    elliptic_curve_point_t sH;
    ecmul_H(s, &sH);
    elliptic_curve_point_t kH;
    ecmul_H(&k, &kH);

    {
        keccak_hasher_t hasher;
        keccak_init(&hasher);
        keccak_update(&hasher, sH.data, sizeof(sH.data));
        keccak_update(&hasher, kH.data, sizeof(kH.data));
        keccak_final_to_scalar(&hasher, &result->c);
    }
    elliptic_curve_scalar_t cs;
    ecmulm(&result->c, s, &cs);
    ecsubm(&k, &cs, &result->r);
}


