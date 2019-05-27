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

#ifndef BYTECOIN_IO_H
#define BYTECOIN_IO_H

#include <stdint.h>
#include "os.h"
#include "bytecoin_crypto.h"

#pragma pack(push)
#pragma pack(1)
typedef struct io_call_params_s
{
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t lc;
//    uint8_t le;
} io_call_params_t;

typedef struct io_call_s
{
    io_call_params_t params;
    uint8_t cdata[0];
} io_call_t;
#pragma pack(pop)

void init_io_call_params(io_call_params_t* ioparams);

#define BYTECOIN_IO_BUFFER_SIZE  IO_APDU_BUFFER_SIZE
#if BYTECOIN_IO_BUFFER_SIZE < 162 // 5*32 bytes in export_view_only +2 bytes for sw
#error BYTECOIN_IO_BUFFER_SIZE is too small
#endif

typedef struct confirm_tx_params_s
{
    public_key_t address_s;
    public_key_t address_sv;
    uint64_t amount;
    uint64_t fee;
    uint8_t address_tag;
}  confirm_tx_params_t;

typedef struct io_buffer_s
{
    uint8_t* data;
    uint16_t length;
    uint16_t offset;
} io_buffer_t;

void init_io_buffer(io_buffer_t* iobuf);

void print_io_call_params(const io_call_params_t* iocall_params);
void print_io_call(const io_call_t* iocall);
void print_io_buffer(const io_buffer_t* iobuf);

void reset_io_buffer(io_buffer_t* iobuf);
void clear_io_buffer(io_buffer_t* iobuf);
int io_do(io_call_params_t* previous_iocall_params, io_buffer_t* iobuf, uint32_t io_flags);

uint64_t fetch_var_from_io_buffer(io_buffer_t* iobuf, uint16_t len);
void fetch_bytes_from_io_buffer(io_buffer_t* iobuf, void* buf, uint16_t len);
elliptic_curve_point_t fetch_point_from_io_buffer(io_buffer_t* iobuf);
elliptic_curve_scalar_t fetch_scalar_from_io_buffer(io_buffer_t* iobuf);
hash_t fetch_hash_from_io_buffer(io_buffer_t* iobuf);

void insert_bytes_to_io_buffer(io_buffer_t* iobuf, const void* buf, uint16_t len);
void insert_var_to_io_buffer(io_buffer_t* iobuf, uint64_t var, uint16_t len);
void insert_scalar_to_io_buffer(io_buffer_t* iobuf, const elliptic_curve_scalar_t* s);
void insert_point_to_io_buffer(io_buffer_t* iobuf, const elliptic_curve_point_t* P);
void insert_hash_to_io_buffer(io_buffer_t* iobuf, const hash_t* h);

#define insert_point(primitive) \
    insert_point_to_io_buffer(&G_bytecoin_vstate.io_buffer, &primitive)

#define insert_scalar(primitive) \
    insert_scalar_to_io_buffer(&G_bytecoin_vstate.io_buffer, &primitive)

#define insert_hash(primitive) \
    insert_hash_to_io_buffer(&G_bytecoin_vstate.io_buffer, &primitive)

#define fetch_point() \
    fetch_point_from_io_buffer(&G_bytecoin_vstate.io_buffer)

#define fetch_scalar() \
    fetch_scalar_from_io_buffer(&G_bytecoin_vstate.io_buffer)

#define fetch_hash() \
    fetch_hash_from_io_buffer(&G_bytecoin_vstate.io_buffer)

#define fetch_var(var_or_type) \
    fetch_var_from_io_buffer(&G_bytecoin_vstate.io_buffer, sizeof(var_or_type))

#define insert_var(var) \
    insert_var_to_io_buffer(&G_bytecoin_vstate.io_buffer, var, sizeof(var))

#define fetch_secret_key  fetch_scalar
#define fetch_public_key  fetch_point
#define fetch_keyimage    fetch_point
#define insert_secret_key insert_scalar
#define insert_public_key insert_point
#define insert_keyimage   insert_point


#endif // BYTECOIN_IO_H
