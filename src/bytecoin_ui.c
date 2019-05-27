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

#include <string.h>
#include "os_io_seproxyhal.h"
#include "bytecoin_ui.h"
#include "bytecoin_ledger_api.h"
#include "glyphs.h"
#include "bytecoin_vars.h"
#include "bytecoin_keys.h"
#include "bytecoin_apdu.h"
#include "bytecoin_debug.h"

extern unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t ux;

#define MENU_CURRENT_ENTRY_ID       0x20 // current entry preprocessor isn't called if line2 is not null
#define MENU_CURRENT_ENTRY_LINE1_ID 0x21 // line1 and line2 preprocessors aren't called if line2 is null
#define MENU_CURRENT_ENTRY_LINE2_ID 0x22

static const char BCN_str[] = " BCN";

void init_ui_data(ui_data_t* ui_data)
{
    os_memset(ui_data, 0, sizeof(ui_data_t));
    ui_data->string_is_valid = false;
}


#if CX_APILEVEL == 8
#define PIN_VERIFIED (!0)
#elif CX_APILEVEL == 9 || CX_APILEVEL == 10
#define PIN_VERIFIED BOLOS_UX_OK
#else
#error CX_APILEVEL not supported
#endif

static
void ask_pin_if_needed(void)
{
    if (os_global_pin_is_validated() != PIN_VERIFIED)
    {
        bolos_ux_params_t params;
        os_memset(&params, 0, sizeof(params));
        params.ux_id = BOLOS_UX_VALIDATE_PIN;
        params.len = 0;
        os_ux_blocking(&params);
    }
}

const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e)
{
    // Go back to the dashboard
    os_sched_exit(0);
    return NULL;
}

static
void ui_menu_info_display(unsigned int value);

static const ux_menu_entry_t ui_menu_main[] = {
//    menu,         callback, userid, icon,              line1,     line2, text_x, icon_x
    { NULL,         NULL,          0, NULL,              "Your address:",         "",  0,      0 },
    { NULL, ui_menu_info_display,          0, NULL,              "About",    NULL,  0,      0 },
    { NULL,         os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50,     29 },
    UX_MENU_END
};

const bagl_element_t* ui_menu_main_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element)
{
    for (size_t i = 0; i < sizeof(ui_menu_main) / sizeof(ui_menu_main[0]); ++i)
    {
        if (entry == &ui_menu_main[i])
        {
            G_bytecoin_vstate.ui_data.current_main_menu_item = i;
            break;
        }
    }

    if (G_bytecoin_vstate.ui_data.current_main_menu_item == 0)
    {
        switch (element->component.userid)
        {
        case MENU_CURRENT_ENTRY_LINE1_ID:
            element->component.font_id = BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER;
            break;
        case MENU_CURRENT_ENTRY_LINE2_ID:
            if (!G_bytecoin_vstate.ui_data.string_is_valid)
            {
                char* addr_str = G_bytecoin_vstate.ui_data.address_str;
                size_t size = sizeof(G_bytecoin_vstate.ui_data.address_str);

                public_key_t address_S;
                public_key_t address_Sv;
                prepare_address_public(&G_bytecoin_vstate.wallet_keys, 0, &address_S, &address_Sv);
                size = encode_address(BYTECOIN_ADDRESS_BASE58_PREFIX_AMETHYST, &address_S, &address_Sv, addr_str, size);
                short_address(addr_str, size);
                G_bytecoin_vstate.ui_data.string_is_valid = true;
            }
//            element->component.stroke = 10;  // 1 sec stop in each way
//            element->component.icon_id = 35; // roundtrip speed in pixel/s
            element->component.width = 105;
            element->text = G_bytecoin_vstate.ui_data.address_str;
//            UX_CALLBACK_SET_INTERVAL(bagl_label_roundtrip_duration_ms(element, 8));
            break;
        }
    }
    return element;
}

static
void ui_menu_main_display(unsigned int value)
{
    G_bytecoin_vstate.ui_data.string_is_valid = false;
    UX_MENU_DISPLAY(G_bytecoin_vstate.ui_data.current_main_menu_item, ui_menu_main, ui_menu_main_preprocessor);
}

const ux_menu_entry_t ui_menu_info[] = {
//    menu, callback,         userid, icon,          line1,                             line2, text_x, icon_x
    { NULL, NULL,                 -1, NULL,          XSTR(BYTECOIN_NAME),                NULL,  0,      0 },
//    { NULL, NULL,                 -1, NULL,          "(c) Bytecoin", " developers ",          0,      0 },
    { NULL, NULL,                 -1, NULL,          "(c) Bytecoin developers ",          NULL,  22,      0 },
    { NULL, NULL,                 -1, NULL,          "Version " XSTR(BYTECOIN_VERSION), NULL,  0,      0 },
    { NULL, NULL,                 -1, NULL,          XSTR(BYTECOIN_SPEC_VERSION),        NULL,  0,      0 },
    { NULL, ui_menu_main_display,  1, &C_badge_back, "Back",                             NULL, 61,     40 },
    UX_MENU_END
};

const bagl_element_t* ui_menu_info_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element)
{
    if (entry == &ui_menu_info[1])
    {
        switch (element->component.userid)
        {
        case MENU_CURRENT_ENTRY_ID:
            element->component.stroke = 5;   // 0.5 sec stop in each way
            element->component.icon_id = 50; // roundtrip speed in pixel/s
            element->component.width = 84;
            UX_CALLBACK_SET_INTERVAL(bagl_label_roundtrip_duration_ms(element, 7));
            break;
        case MENU_CURRENT_ENTRY_LINE1_ID:
        case MENU_CURRENT_ENTRY_LINE2_ID:
            element->component.font_id = (element->component.font_id & BAGL_FONT_ID_MASK) | BAGL_FONT_ALIGNMENT_CENTER;
            break;
        }
    }
    return element;
}

void ui_menu_info_display(unsigned int value)
{
    UX_MENU_DISPLAY(value, ui_menu_info, ui_menu_info_preprocessor);
}


void ui_init(void)
{
    ui_menu_main_display(0);
// setup the first screen changing
    UX_CALLBACK_SET_INTERVAL(1000);
}

void io_seproxyhal_display(const bagl_element_t *element)
{
    io_seproxyhal_display_default(element);
}

static
const bagl_element_t* ui_export_viewkey_preprocessor(const bagl_element_t* element);

static
unsigned int ui_export_viewkey_button(unsigned int button_mask, unsigned int button_mask_counter);


 const bagl_element_t ui_export_viewkey[] = {
  // type             userid    x    y    w    h    str   rad  fill              fg        bg     font_id                   icon_id
  { {BAGL_RECTANGLE,  0x00,     0,   0, 128,  32,    0,    0,  BAGL_FILL,  0x000000, 0xFFFFFF,    0,                         0},
    NULL,
    0,
    0, 0,
    NULL, NULL, NULL},

  { {BAGL_ICON,       0x00,    3,   12,   7,   7,    0,    0,         0,   0xFFFFFF, 0x000000,    0,                          BAGL_GLYPH_ICON_CROSS  },
    NULL,
    0,
    0, 0,
    NULL, NULL, NULL },

  { {BAGL_ICON,       0x00,  117,   13,   8,   6,    0,    0,         0,   0xFFFFFF, 0x000000,    0,                          BAGL_GLYPH_ICON_CHECK  },
     NULL,
     0,
     0, 0,
     NULL, NULL, NULL },

  { {BAGL_LABELINE,   0x01,    0,   12, 128,  32,    0,    0,         0,   0xFFFFFF, 0x000000,    BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0  },
    G_bytecoin_vstate.ui_data.address_str,
    0,
    0, 0,
    NULL, NULL, NULL },

  { {BAGL_LABELINE,   0x02,    0,   26, 128,  32,    0,    0,         0,   0xFFFFFF, 0x000000,    BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0  },
    G_bytecoin_vstate.ui_data.address_str,
    0,
    0, 0,
    NULL, NULL, NULL },
};

static
const bagl_element_t* ui_export_viewkey_preprocessor(const bagl_element_t* element)
{
    G_bytecoin_vstate.ui_data.string_is_valid = false;
    if (element->component.userid == 1)
        snprintf(G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str), "Export");
    else if (element->component.userid == 2)
        snprintf(G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str), "view wallet?");
    else
        snprintf(G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str), "Please Cancel");
    return element;
}

static
unsigned int ui_export_viewkey_button(unsigned int button_mask, unsigned int button_mask_counter)
{
    uint16_t sw = 0;
    switch(button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        sw = SW_SECURITY_STATUS_NOT_SATISFIED;
        break;
    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:  // OK
          return user_confirm_view_outgoing_addresses();
        break;
    default:
        return 0;
    }
    insert_var(sw);
    io_do(&G_bytecoin_vstate.prev_io_call_params, &G_bytecoin_vstate.io_buffer, IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
    return 0;
}

int user_confirm_export_view_only(void)
{
    ask_pin_if_needed();
    UX_DISPLAY(ui_export_viewkey, ui_export_viewkey_preprocessor);
    return 0;
}



static
const bagl_element_t ui_view_outgoing_addresses[] = {
  // type             userid    x    y    w    h    str   rad  fill              fg        bg     font_id                   icon_id
  { {BAGL_RECTANGLE,  0x00,     0,   0, 128,  32,    0,    0,  BAGL_FILL,  0x000000, 0xFFFFFF,    0,                         0},
    NULL,
    0,
    0, 0,
    NULL, NULL, NULL},

  { {BAGL_ICON,       0x00,    3,   12,   7,   7,    0,    0,         0,   0xFFFFFF, 0x000000,    0,                          BAGL_GLYPH_ICON_CROSS  },
    NULL,
    0,
    0, 0,
    NULL, NULL, NULL },

  { {BAGL_ICON,       0x00,  117,   13,   8,   6,    0,    0,         0,   0xFFFFFF, 0x000000,    0,                          BAGL_GLYPH_ICON_CHECK  },
     NULL,
     0,
     0, 0,
     NULL, NULL, NULL },

  { {BAGL_LABELINE,   0x01,    0,   12, 128,  32,    0,    0,         0,   0xFFFFFF, 0x000000,    BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0  },
    G_bytecoin_vstate.ui_data.address_str,
    0,
    0, 0,
    NULL, NULL, NULL },

  { {BAGL_LABELINE,   0x02,    0,   26, 128,  32,    0,    0,         0,   0xFFFFFF, 0x000000,    BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0  },
    G_bytecoin_vstate.ui_data.address_str,
    0,
    0, 0,
    NULL, NULL, NULL },
};

static
const bagl_element_t* ui_view_outgoing_addresses_preprocessor(const bagl_element_t* element)
{
    G_bytecoin_vstate.ui_data.string_is_valid = false;
    if (element->component.userid == 1)
        snprintf(G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str), "Allow to view");
    else if (element->component.userid == 2)
        snprintf(G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str), "outgoing addrs.?");
    else
        snprintf(G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str), "Please Cancel");
    return element;
}

static
unsigned int ui_view_outgoing_addresses_button(unsigned int button_mask, unsigned int button_mask_counter)
{
    bool allow = false;
    switch(button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        allow = false;
        break;
    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:  // OK
        allow = true;
        break;
    default:
        return 0;
    }
    const uint16_t sw = bytecoin_apdu_export_view_only_final(allow);
    insert_var(sw);
    io_do(&G_bytecoin_vstate.prev_io_call_params, &G_bytecoin_vstate.io_buffer, IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
    return 0;
}

int user_confirm_view_outgoing_addresses(void)
{
    ask_pin_if_needed();
    UX_DISPLAY(ui_view_outgoing_addresses, ui_view_outgoing_addresses_preprocessor);
    return 0;
}

#define NUMBER_OF_DECIMAL_PLACES 8

//static
//size_t amount2str_old(uint64_t amount, char* amount_str, size_t str_len)
//{
//    os_memset(amount_str, 0, str_len);

//    if (amount == 0)
//    {
//        amount_str[0] = '0';
//        return 1;
//    }

//    size_t amount_len = 0;
//    for (uint64_t amount_rem = amount; amount_rem != 0; amount_rem /= 10)
//        ++amount_len;

//    for (size_t offset = 0; amount != 0; amount /= 10)
//        amount_str[amount_len - (offset++) - 1] = (char)(amount % 10) + '0';

//    if (amount_len < NUMBER_OF_DECIMAL_PLACES)
//    {
//        os_memmove(amount_str + NUMBER_OF_DECIMAL_PLACES - amount_len + 2, amount_str, amount_len);
//        os_memset(amount_str, '0', NUMBER_OF_DECIMAL_PLACES - amount_len + 2);
//        amount_str[1] = '.';
//        amount_len += NUMBER_OF_DECIMAL_PLACES - amount_len + 2;
//    }
//    else if (amount_len == NUMBER_OF_DECIMAL_PLACES)
//    {
//        os_memmove(amount_str + 2, amount_str, amount_len);
//        amount_str[0] = '0';
//        amount_str[1] = '.';
//        amount_len += 2;
//    }
//    else
//    {
//        os_memmove(amount_str + amount_len - NUMBER_OF_DECIMAL_PLACES + 1, amount_str + amount_len - NUMBER_OF_DECIMAL_PLACES, NUMBER_OF_DECIMAL_PLACES);
//        amount_str[amount_len - NUMBER_OF_DECIMAL_PLACES] = '.';
//        amount_len += 1;
//    }

//    for (size_t offset = amount_len - 1; amount_str[offset] == '0' && amount_str[offset - 1] != '.'; --offset)
//    {
//        amount_str[offset] = 0;
//        --amount_len;
//    }

//    return amount_len;
//}

static
void ffw(uint64_t amount, size_t digs, char* buf)
{
    for(; digs > 0; digs -=1)
    {
        const uint64_t d = amount % 10;
        amount /= 10;
        buf[digs - 1] = '0' + d;
    }
}

static
size_t amount2str(uint64_t amount, char* buffer, size_t len)
{
    const size_t COIN = 100000000;
    const size_t CENT = COIN / 100;
    uint64_t ia = amount / COIN;
    uint64_t fa = amount - ia * COIN;
    size_t pos = 0;

    while (ia >= 1000)
    {
        pos += 4;
        os_memmove(buffer + 4, buffer, pos);
        buffer[0] = '\'';
        ffw(ia % 1000, 3, buffer + 1);
        ia /= 1000;
    }

    while(true)
    {
        uint64_t d = ia % 10;
        ia = ia / 10;
        pos += 1;
        memmove(buffer + 1, buffer, pos);
        buffer[0] = '0' + d;
        if(ia == 0)
          break;
    }

    if (fa != 0)
    {  // cents
        buffer[pos++] = '.';
        ffw(fa / CENT, 2, buffer + pos);
        pos += 2;
        fa %= CENT;
    }

    if (fa != 0)
    {
    //    buffer[pos++] = '\'';
        ffw(fa / 1000, 3, buffer + pos);
        pos += 3;
        fa %= 1000;
    }
    if (fa != 0)
    {
    //    buffer[pos++] = '\'';
        ffw(fa, 3, buffer + pos);
        pos += 3;
    }
    return pos;
}

#define BYTECOIN_SIMPLE_ADDRESS_TAG     0
#define BYTECOIN_UNLINKABLE_ADDRESS_TAG 1

static
void ui_confirm_tx_reject_action(unsigned int value);
static
void ui_confirm_tx_accept_action(unsigned int value);

static const ux_menu_entry_t ui_menu_confirm_tx[] = {
//    menu,         callback, userid, icon,              line1,     line2, text_x, icon_x
    { NULL,         NULL,          1, NULL,              "Recipient address:",         "",  0,      0 },
    { NULL, NULL,          2, NULL,              "Amount:",    "",  0,      0 },
    { NULL,         NULL, 3, NULL,                "Fee:", "", 0,     0 },
    {NULL,  ui_confirm_tx_reject_action,  4, NULL,  "Reject Tx",       NULL,         0, 0},
    {NULL,  ui_confirm_tx_accept_action,  5, NULL,  "Approve Tx",       NULL,         0, 0},
    UX_MENU_END
};

static
const bagl_element_t* ui_menu_confirm_tx_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element)
{
    const bytecoin_signing_state_t* sig_state = &G_bytecoin_vstate.sig_state;
    if (entry == &ui_menu_confirm_tx[0])
    {
        switch (element->component.userid)
        {
        case MENU_CURRENT_ENTRY_LINE1_ID:
            element->component.font_id = BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER;
            break;
        case MENU_CURRENT_ENTRY_LINE2_ID:
            {
                const uint64_t prefix = (sig_state->dst_address_tag == BYTECOIN_UNLINKABLE_ADDRESS_TAG) ? BYTECOIN_ADDRESS_BASE58_PREFIX_AMETHYST : BYTECOIN_ADDRESS_BASE58_PREFIX;
                encode_address(prefix, &sig_state->dst_address_s, &sig_state->dst_address_s_v, G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str) - 1);

                element->component.stroke = 10;  // 1 sec stop in each way
                element->component.icon_id = 35; // roundtrip speed in pixel/s
                element->component.width = 95;
                element->text = G_bytecoin_vstate.ui_data.address_str;
                UX_CALLBACK_SET_INTERVAL(bagl_label_roundtrip_duration_ms(element, 8));
            }
            break;
        }
    }

    if (entry == &ui_menu_confirm_tx[1])
    {
        switch (element->component.userid)
        {
        case MENU_CURRENT_ENTRY_LINE1_ID:
            element->component.font_id = BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER;
            break;
        case MENU_CURRENT_ENTRY_LINE2_ID:
            {
                const size_t len = amount2str(sig_state->dst_amount, G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str));
                if (len + sizeof(BCN_str) > sizeof(G_bytecoin_vstate.ui_data.address_str))
                    THROW(SW_NOT_ENOUGH_MEMORY);
                ;
                os_memmove(G_bytecoin_vstate.ui_data.address_str + len, BCN_str, sizeof(BCN_str));

                element->component.stroke = 10;  // 1 sec stop in each way
                element->component.icon_id = 35; // roundtrip speed in pixel/s
                element->component.width = 95;
                element->text = G_bytecoin_vstate.ui_data.address_str;
                UX_CALLBACK_SET_INTERVAL(bagl_label_roundtrip_duration_ms(element, 8));
            }
            break;
        }
    }

    if (entry == &ui_menu_confirm_tx[2])
    {
        switch (element->component.userid)
        {
        case MENU_CURRENT_ENTRY_LINE1_ID:
            element->component.font_id = BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER;
            break;
        case MENU_CURRENT_ENTRY_LINE2_ID:
            {
                const size_t len = amount2str(sig_state->dst_fee, G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str));
                if (len + sizeof(BCN_str) > sizeof(G_bytecoin_vstate.ui_data.address_str))
                    THROW(SW_NOT_ENOUGH_MEMORY);
                os_memmove(G_bytecoin_vstate.ui_data.address_str + len, BCN_str, sizeof(BCN_str));

                element->component.stroke = 10;  // 1 sec stop in each way
                element->component.icon_id = 35; // roundtrip speed in pixel/s
                element->component.width = 95;
                element->text = G_bytecoin_vstate.ui_data.address_str;
                UX_CALLBACK_SET_INTERVAL(bagl_label_roundtrip_duration_ms(element, 8));
            }
            break;
        }
    }

    return element;
}

static
void ui_confirm_tx_reject_action(unsigned int value)
{
    const uint16_t sw = SW_SECURITY_STATUS_NOT_SATISFIED;
    insert_var(sw);
    io_do(&G_bytecoin_vstate.prev_io_call_params, &G_bytecoin_vstate.io_buffer, IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
}

static
void ui_confirm_tx_accept_action(unsigned int value)
{
    const uint16_t sw = bytecoin_apdu_sig_add_output_final();
    insert_var(sw);
    io_do(&G_bytecoin_vstate.prev_io_call_params, &G_bytecoin_vstate.io_buffer, IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
}


int user_confirm_tx(void)
{
    G_bytecoin_vstate.ui_data.string_is_valid = false;

    ask_pin_if_needed();
    UX_MENU_DISPLAY(0, ui_menu_confirm_tx, ui_menu_confirm_tx_preprocessor);

    return 0;
}


