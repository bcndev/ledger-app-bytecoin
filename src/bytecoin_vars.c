#include "bytecoin_vars.h"

void init_vstate(bytecoin_v_state_t* state)
{
    init_io_buffer(&state->io_buffer);
    init_signing_state(&state->sig_state);
    init_wallet_keys(&state->wallet_keys);
    init_ui_data(&state->ui_data);
    init_io_call_params(&state->prev_io_call_params);
}
