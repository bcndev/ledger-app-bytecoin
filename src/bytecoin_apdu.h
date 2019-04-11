#ifndef BYTECOIN_APDU_H
#define BYTECOIN_APDU_H

#include <stdbool.h>

int bytecoin_apdu_get_wallet_keys(void);

int bytecoin_apdu_scan_outputs(void);
int bytecoin_apdu_generate_keyimage(void);
int bytecoin_apdu_generate_output_seed(void);
int bytecoin_apdu_export_view_only(void);
int bytecoin_apdu_export_view_only_final(bool view_outgoing_addresses);

int bytecoin_apdu_sig_start(void);
int bytecoin_apdu_sig_add_input_start(void);
int bytecoin_apdu_sig_add_input_indexes(void);
int bytecoin_apdu_sig_add_input_finish(void);
int bytecoin_apdu_sig_add_output(void);
int bytecoin_apdu_sig_add_output_final(void);
int bytecoin_apdu_sig_add_extra(void);
int bytecoin_apdu_sig_step_a(void);
int bytecoin_apdu_sig_step_a_more_data(void);
int bytecoin_apdu_sig_get_c0(void);
int bytecoin_apdu_sig_step_b(void);
int bytecoin_apdu_sig_proof_start(void);

#endif // BYTECOIN_APDU_H
