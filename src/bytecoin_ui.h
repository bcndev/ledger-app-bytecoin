#ifndef BYTECOIN_UI_H
#define BYTECOIN_UI_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "bytecoin_crypto.h"

#define BYTECOIN_ADDRESS_LENGTH 98

typedef struct ui_data_s
{
    char address_str[BYTECOIN_ADDRESS_LENGTH + 1];
    size_t current_main_menu_item;
    bool string_is_valid;
} ui_data_t;

void init_ui_data(ui_data_t* ui_data);
void ui_init(void);

int user_confirm_export_view_only(void);

// ask user if he/she wants view wallet to view outgoing addresses
int user_confirm_view_outgoing_addresses(void);

int user_confirm_tx(/*uint64_t amount, const public_key_t* dst_address_s, const public_key_t* dst_address_s_v, uint8_t dst_address_tag, uint64_t fee*/);

#endif // BYTECOIN_UI_H
