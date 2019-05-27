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
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "bytecoin_ledger_api.h"
#include "bytecoin_vars.h"
#include "bytecoin_apdu.h"
#include "bytecoin_ui.h"

bytecoin_v_state_t G_bytecoin_vstate;

int dispatch(uint8_t cla, uint8_t ins)
{
    int sw = SW_INS_NOT_SUPPORTED;

    if (cla != BYTECOIN_CLA)
    {
        THROW(SW_CLA_NOT_SUPPORTED);
        return SW_CLA_NOT_SUPPORTED;
    }

    switch(ins)
    {
    case INS_RESET:
        reset_io_buffer(&G_bytecoin_vstate.io_buffer);
        return SW_NO_ERROR;

    case INS_GET_APP_INFO:
        sw = bytecoin_apdu_get_ledger_app_info(); break;
    case INS_GET_WALLET_KEYS:
        sw = bytecoin_apdu_get_wallet_keys(); break;
    case INS_SCAN_OUTPUTS:
        sw = bytecoin_apdu_scan_outputs(); break;
    case INS_GENERATE_KEYIMAGE:
        sw = bytecoin_apdu_generate_keyimage(); break;
    case INS_GENERATE_OUTPUT_SEED:
        sw = bytecoin_apdu_generate_output_seed(); break;
    case INS_SIG_START:
        sw = bytecoin_apdu_sig_start(); break;
    case INS_SIG_ADD_INPUT_START:
        sw = bytecoin_apdu_sig_add_input_start(); break;
    case INS_SIG_ADD_INPUT_INDEXES:
        sw = bytecoin_apdu_sig_add_input_indexes(); break;
    case INS_SIG_ADD_INPUT_FINISH:
        sw = bytecoin_apdu_sig_add_input_finish(); break;
    case INS_SIG_ADD_OUPUT:
        sw = bytecoin_apdu_sig_add_output(); break;
    case INS_SIG_ADD_EXTRA:
        sw = bytecoin_apdu_sig_add_extra(); break;
    case INS_SIG_STEP_A:
        sw = bytecoin_apdu_sig_step_a(); break;
    case INS_SIG_STEP_A_MORE_DATA:
        sw = bytecoin_apdu_sig_step_a_more_data(); break;
    case INS_SIG_GET_C0:
        sw = bytecoin_apdu_sig_get_c0(); break;
    case INS_SIG_STEP_B:
        sw = bytecoin_apdu_sig_step_b(); break;
    case INS_SIG_PROOF_START:
        sw = bytecoin_apdu_sig_proof_start(); break;
    case INS_EXPORT_VIEW_ONLY:
        sw = bytecoin_apdu_export_view_only(); break;

    default:
      THROW(SW_INS_NOT_SUPPORTED);
      return SW_INS_NOT_SUPPORTED;
      break;
    }
    return sw;
}

static
void bytecoin_main(void)
{
    volatile uint32_t io_flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;)
    {
        volatile uint16_t sw = 0;

        BEGIN_TRY {
            TRY {
                io_do(&G_bytecoin_vstate.prev_io_call_params, &G_bytecoin_vstate.io_buffer, io_flags);
                sw = dispatch(G_bytecoin_vstate.prev_io_call_params.cla, G_bytecoin_vstate.prev_io_call_params.ins);
            }
            CATCH_OTHER(e) {
                clear_io_buffer(&G_bytecoin_vstate.io_buffer);

                if ((e & 0xF000) != 0x6000 && (e & 0xF000) != 0x9000)
                {
                    insert_var(e);
                    sw = SW_SOMETHING_WRONG;
                }
                else
                    sw = e;
            }
            FINALLY {
                if (sw)
                {
                    insert_var(sw);
                    io_flags = 0;
                }
                else
                  io_flags = IO_ASYNCH_REPLY;
            }
        }
        END_TRY;
    }

    return;
}

void app_exit(void) {
  BEGIN_TRY_L(exit) {
    TRY_L(exit) {
      os_sched_exit(-1);
    }
    FINALLY_L(exit) {
    }
  }
  END_TRY_L(exit);
}

__attribute__((section(".boot")))
int main(void)
{
    // exit critical section
    __asm volatile("cpsie i");

    os_boot();
    for(;;) {
      UX_INIT();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            USB_power(0);
            USB_power(1);

            #ifdef HAVE_USB_CLASS_CCID
            io_usb_ccid_set_card_inserted(1);
            #endif

            init_vstate(&G_bytecoin_vstate);
            ui_init();

            bytecoin_main();
        }
        CATCH(EXCEPTION_IO_RESET) {
        // reset IO and UX
          continue;
        }
        CATCH_ALL {
          break;
        }
        FINALLY {
        }
      }
      END_TRY;
    }
    app_exit();
}
