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

#ifndef BYTECOIN_VARS_H
#define BYTECOIN_VARS_H

#include "bytecoin_io.h"
#include "bytecoin_sig.h"
#include "bytecoin_wallet.h"
#include "bytecoin_ui.h"

typedef struct bytecoin_v_state_s
{
    io_buffer_t io_buffer;
    bytecoin_signing_state_t sig_state;
    wallet_keys_t wallet_keys;
    ui_data_t ui_data;
    io_call_params_t prev_io_call_params;
} bytecoin_v_state_t;

void init_vstate(bytecoin_v_state_t* state);

extern bytecoin_v_state_t G_bytecoin_vstate;

#endif // BYTECOIN_VARS_H
