#include "os_io_seproxyhal.h"
#include "bytecoin_ui.h"
#include "bytecoin_ledger_api.h"
#include "glyphs.h"
#include "bytecoin_vars.h"
#include "bytecoin_keys.h"
#include "bytecoin_apdu.h"
#include "bytecoin_io.h"
#include <string.h>


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
                public_key_t address_S;
                public_key_t address_Sv;
                prepare_address_public(&G_bytecoin_vstate.wallet_keys, 0, &address_S, &address_Sv);
                encode_address(BYTECOIN_ADDRESS_BASE58_PREFIX_AMETHYST, &address_S, &address_Sv, G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str) - 1);
                G_bytecoin_vstate.ui_data.string_is_valid = true;
            }
            element->component.stroke = 10;  // 1 sec stop in each way
            element->component.icon_id = 35; // roundtrip speed in pixel/s
            element->component.width = 95;
            element->text = G_bytecoin_vstate.ui_data.address_str;
            UX_CALLBACK_SET_INTERVAL(bagl_label_roundtrip_duration_ms(element, 8));
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
    { NULL, NULL,                 -1, NULL,          XSTR(SPEC_VERSION),        NULL,  0,      0 },
    { NULL, ui_menu_main_display,  1, &C_badge_back, "Back",                             NULL, 61,     40 },
    UX_MENU_END
};

const bagl_element_t* ui_menu_info_preprocessor(const ux_menu_entry_t* entry, bagl_element_t* element)
{
    if (entry == &ui_menu_info[1])
    {
//        PRINTF("userid: %d\n", element->component.userid);
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
//        sw = bytecoin_apdu_export_view_only_impl(true);
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
    UX_DISPLAY(ui_view_outgoing_addresses, ui_view_outgoing_addresses_preprocessor);
    return 0;
}

static
size_t amount2str(uint64_t amount, char *str, unsigned int str_len)
{
    uint64_t amount_rem;
    size_t len,i;
    os_memset(str,0,str_len);

    //special case
   if (amount == 0) {
        str[0] = '0';
        return 1;
    }
    //How many str digit
    amount_rem = amount;
    len = 0;
    while (amount_rem != 0) {
        len++;
        amount_rem /= 10;
    }

    //uint64 units to str
    str_len--;
    for (i = 0; i < len; i++) {
        if ((len - (i + 1)) > str_len) {
            amount = amount / 10;
            continue;
        }
        amount_rem = amount % 10;
        amount = amount / 10;
        str[len - (i + 1)] = amount_rem + '0';
    }
    str[len] = 0;

    //units to decimal amount
    len = 0;
    while(str[len]) {
        len++;
    }
    if (len>12) {
        os_memmove(str+len-12+1,str+len-12, 12);
        str[len-12] = '.';
        len++;
    } else {
        i = (12-len)+2;
        os_memmove(str+i, str, len);
        os_memset(str,'0',i);
        str[1] = '.';
        len += i;
    }

    //trim trailing zero
    len--;
    while (str[len] == '0') {
        str[len] = 0;
        len--;
    }
    return len;
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
    const confirm_tx_params_t* params = &G_bytecoin_vstate.io_buffer.confirm_tx_params;
    if (entry == &ui_menu_confirm_tx[0])
    {
        switch (element->component.userid)
        {
        case MENU_CURRENT_ENTRY_LINE1_ID:
            element->component.font_id = BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER;
            break;
        case MENU_CURRENT_ENTRY_LINE2_ID:
            {
                const uint64_t prefix = (params->address_tag == BYTECOIN_UNLINKABLE_ADDRESS_TAG) ? BYTECOIN_ADDRESS_BASE58_PREFIX_AMETHYST : BYTECOIN_ADDRESS_BASE58_PREFIX;
                encode_address(prefix, &params->address_s, &params->address_sv, G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str) - 1);

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
                const size_t len = amount2str(params->amount, G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str) - 1) + 1;
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

    if (entry == &ui_menu_confirm_tx[2])
    {
        switch (element->component.userid)
        {
        case MENU_CURRENT_ENTRY_LINE1_ID:
            element->component.font_id = BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER;
            break;
        case MENU_CURRENT_ENTRY_LINE2_ID:
            {
                const size_t len = amount2str(params->fee, G_bytecoin_vstate.ui_data.address_str, sizeof(G_bytecoin_vstate.ui_data.address_str) - 1) + 1;
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

int user_confirm_tx(uint64_t amount, const public_key_t* dst_address_s, const public_key_t* dst_address_s_v, uint8_t dst_address_tag, uint64_t fee)
{
    G_bytecoin_vstate.io_buffer.confirm_tx_params.address_s = *dst_address_s;
    G_bytecoin_vstate.io_buffer.confirm_tx_params.address_sv = *dst_address_s_v;
    G_bytecoin_vstate.io_buffer.confirm_tx_params.amount = amount;
    G_bytecoin_vstate.io_buffer.confirm_tx_params.fee = fee;
    G_bytecoin_vstate.io_buffer.confirm_tx_params.address_tag = dst_address_tag;

    G_bytecoin_vstate.ui_data.string_is_valid = false;
    UX_MENU_DISPLAY(0, ui_menu_confirm_tx, ui_menu_confirm_tx_preprocessor);

    return 0;
}


