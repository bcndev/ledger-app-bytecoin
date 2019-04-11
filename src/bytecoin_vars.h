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
