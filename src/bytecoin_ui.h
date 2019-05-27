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

#ifndef BYTECOIN_UI_H
#define BYTECOIN_UI_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

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

// ask user if he/she wants to allow view wallet to view outgoing addresses
int user_confirm_view_outgoing_addresses(void);

int user_confirm_tx(void);

#endif // BYTECOIN_UI_H
