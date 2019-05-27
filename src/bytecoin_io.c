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
#include "os_io_seproxyhal.h"
#include "bytecoin_io.h"
#include "bytecoin_ledger_api.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

void init_io_call_params(io_call_params_t* ioparams)
{
    os_memset(ioparams, 0, sizeof(io_call_params_t));
}

void init_io_buffer(io_buffer_t* iobuf)
{
    os_memset(iobuf, 0 , sizeof(io_buffer_t));
    iobuf->data = G_io_apdu_buffer;
}

static
void check_available(const io_buffer_t* iobuf, uint16_t len)
{
    if (iobuf->length < iobuf->offset)
        THROW(SW_CONDITIONS_NOT_SATISFIED);
    if (iobuf->length - iobuf->offset < len)
        THROW(SW_WRONG_LENGTH + (len & 0xFF));
}

static
void make_hole(io_buffer_t* iobuf, uint16_t len)
{
    if (iobuf->length + len > BYTECOIN_IO_BUFFER_SIZE)
        THROW(SW_NOT_ENOUGH_MEMORY);
    if (iobuf->length < iobuf->offset)
        THROW(SW_CONDITIONS_NOT_SATISFIED);

    const void* src = iobuf->data + iobuf->offset;
          void* dst = iobuf->data + iobuf->offset + len;
    const uint16_t size = iobuf->length - iobuf->offset;

    os_memmove(dst, src, size);
    iobuf->length += len;
}

void fetch_bytes_from_io_buffer(io_buffer_t* iobuf, void* buf, uint16_t len)
{
    if (!buf)
        return;
    check_available(iobuf, len);
    os_memmove(buf, iobuf->data + iobuf->offset, len);
    iobuf->offset += len;
}

void insert_bytes_to_io_buffer(io_buffer_t* iobuf, const void* buf, uint16_t len)
{
    make_hole(iobuf, len);
    os_memmove(iobuf->data + iobuf->offset, buf, len);
    iobuf->offset += len;
}

static
void fetch_reversed_bytes_from_io_buffer(io_buffer_t* iobuf, void* buf, uint16_t len)
{
    if (!buf)
        return;
    check_available(iobuf, len);
    reverse(buf, iobuf->data + iobuf->offset, len);
    iobuf->offset += len;
}

static
void insert_reversed_bytes_to_io_buffer(io_buffer_t* iobuf, const void* buf, uint16_t len)
{
    make_hole(iobuf, len);
    reverse(iobuf->data + iobuf->offset, buf, len);
    iobuf->offset += len;
}

elliptic_curve_scalar_t fetch_scalar_from_io_buffer(io_buffer_t* iobuf)
{
    elliptic_curve_scalar_t result;
    fetch_reversed_bytes_from_io_buffer(iobuf, result.data, sizeof(result.data));
    return result;
}

elliptic_curve_point_t fetch_point_from_io_buffer(io_buffer_t* iobuf)
{
    elliptic_curve_point_t result;
    fetch_bytes_from_io_buffer(iobuf, result.data, sizeof(result.data));
    return result;
}

hash_t fetch_hash_from_io_buffer(io_buffer_t* iobuf)
{
    hash_t result;
    fetch_bytes_from_io_buffer(iobuf, result.data, sizeof(result.data));
    return result;
}

void insert_var_to_io_buffer(io_buffer_t* iobuf, uint64_t var, uint16_t len)
{
    make_hole(iobuf, len);
    for (uint16_t i = 0; i < len; ++i)
        iobuf->data[iobuf->offset++] = (var >> ((len - i - 1) * 8));
}

void insert_scalar_to_io_buffer(io_buffer_t* iobuf, const elliptic_curve_scalar_t* s)
{
    insert_reversed_bytes_to_io_buffer(iobuf, s->data, sizeof(s->data));
}

void insert_point_to_io_buffer(io_buffer_t* iobuf, const elliptic_curve_point_t* P)
{
    insert_bytes_to_io_buffer(iobuf, P->data, sizeof(P->data));
}

void insert_hash_to_io_buffer(io_buffer_t* iobuf, const hash_t* h)
{
    insert_bytes_to_io_buffer(iobuf, h->data, sizeof(h->data));
}

uint64_t fetch_var_from_io_buffer(io_buffer_t* iobuf, uint16_t len)
{
    check_available(iobuf, len);
    uint64_t var = 0;
    for (uint16_t i = 0; i < len; ++i)
        var |= ((uint64_t)iobuf->data[iobuf->offset++]) << ((len - i - 1) * 8);
    return var;
}

void reset_io_buffer(io_buffer_t* iobuf)
{
    iobuf->offset = 0;
    iobuf->length = 0;
}

void clear_io_buffer(io_buffer_t* iobuf)
{
    reset_io_buffer(iobuf);
    os_memset(iobuf->data, 0, BYTECOIN_IO_BUFFER_SIZE);
}

#define MAX_OUT 0xFE
#if (MAX_OUT > IO_APDU_BUFFER_SIZE)
#error MAX_OUT must be less than size of G_io_apdu_buffer
#endif

// chaining flag is in bit 5 of cla. see 5.1.1.1 of ISO/IEC 7816-4
#define CHAINING_BIT 0x10

int io_do(io_call_params_t* previous_iocall_params, io_buffer_t* iobuf, uint32_t io_flags)
{
    const io_call_t* new_iocall = (const io_call_t*)G_io_apdu_buffer;
    if (previous_iocall_params->cla & CHAINING_BIT)
        goto in_chaining;

    if (io_flags & IO_ASYNCH_REPLY)
    {
        // if IO_ASYNCH_REPLY has been set,
        // io_exchange will return when IO_RETURN_AFTER_TX will set in ui
        io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);
    }
    else
    {
        // full out chaining
        iobuf->offset = 0;
        while(iobuf->length > MAX_OUT)
        {
            const uint32_t tx =  MAX_OUT - 2;
//            os_memmove(G_io_apdu_buffer, iobuf->data + iobuf->offset, tx);
            iobuf->length -= tx;
            iobuf->offset += tx;
            G_io_apdu_buffer[tx] = (SW_BYTES_REMAINING_00 >> 8);
            G_io_apdu_buffer[tx + 1] = (iobuf->length > MAX_OUT - 2) ? MAX_OUT - 2 : iobuf->length - 2;
            io_exchange(CHANNEL_APDU, tx + 2);

            // check get response
            if (new_iocall->params.cla != BYTECOIN_CLA ||
                new_iocall->params.ins != INS_GET_RESPONSE ||
                new_iocall->params.p1 != 0x00 ||
                new_iocall->params.p2 != 0x00)
            {
                THROW(SW_COMMAND_NOT_ALLOWED);
                return 0;
            }
        }
//        os_memmove(G_io_apdu_buffer, iobuf->data + iobuf->offset, iobuf->length);

        if (io_flags & IO_RETURN_AFTER_TX)
        {
            io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, iobuf->length);
            return 0;
        }
        else
        {
            io_exchange(CHANNEL_APDU,  iobuf->length);
        }
    }

    // full in chaining
    reset_io_buffer(iobuf);

    // save params
    *previous_iocall_params = new_iocall->params;
    // save cdata
#if BYTECOIN_IO_BUFFER_SIZE < UINT8_MAX // disable warning if BYTECOIN_IO_BUFFER_SIZE > 255
    if (new_iocall->params.lc > BYTECOIN_IO_BUFFER_SIZE)
    {
        PRINTF("SW_NOT_ENOUGH_MEMORY lc=%d\n", (int)new_iocall->params.lc);
        THROW(SW_NOT_ENOUGH_MEMORY + new_iocall->params.lc);
        return SW_NOT_ENOUGH_MEMORY;
    }
#endif
    os_memmove(iobuf->data + iobuf->offset, new_iocall->cdata, new_iocall->params.lc);
    iobuf->length =  previous_iocall_params->lc;

    while(previous_iocall_params->cla & CHAINING_BIT)
    {
        G_io_apdu_buffer[0] = (SW_NO_ERROR >> 8);
        G_io_apdu_buffer[1] = (uint8_t)SW_NO_ERROR;
        io_exchange(CHANNEL_APDU, 2);
in_chaining:
        {
            if (((new_iocall->params.cla & (~CHAINING_BIT)) != (previous_iocall_params->cla & (~CHAINING_BIT))) ||
                (new_iocall->params.ins != previous_iocall_params->ins) ||
                (new_iocall->params.p1 != previous_iocall_params->p1) ||
                (new_iocall->params.p2 != previous_iocall_params->p2) )
            {
                THROW(SW_COMMAND_NOT_ALLOWED);
                return SW_COMMAND_NOT_ALLOWED;
            }
            previous_iocall_params->cla = new_iocall->params.cla;
            previous_iocall_params->lc  = new_iocall->params.lc;
            if ((iobuf->length + previous_iocall_params->lc) > BYTECOIN_IO_BUFFER_SIZE)
            {
                THROW(SW_NOT_ENOUGH_MEMORY);
                return SW_NOT_ENOUGH_MEMORY;
            }
            os_memmove(iobuf->data + iobuf->length, new_iocall->cdata, new_iocall->params.lc);
            iobuf->length += new_iocall->params.lc;
        }
    }
    return 0;
}

void print_io_call_params(const io_call_params_t* iocall_params)
{
    PRINTF("iocall_params:\n");
    PRINTF("cla=%.*h\n", 1, &iocall_params->cla);
    PRINTF("ins=%.*h\n", 1, &iocall_params->ins);
    PRINTF("p1 =%.*h\n", 1, &iocall_params->p1);
    PRINTF("p2 =%.*h\n", 1, &iocall_params->p2);
    PRINTF("lc =%.*h\n", 1, &iocall_params->lc);
}

void print_io_call(const io_call_t* iocall)
{
    print_io_call_params(&iocall->params);
    PRINTF("iocall cdata=%.*h\n", iocall->params.lc, iocall->cdata);
}

void print_io_buffer(const io_buffer_t* iobuf)
{
    PRINTF("io_buffer_t:\n");
    PRINTF("length=%d\n", iobuf->length);
    PRINTF("offset=%d\n", iobuf->offset);
    PRINTF("data=%.*h\n", sizeof(iobuf->data), iobuf->data);
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len)
{
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

unsigned char io_event(unsigned char channel) {
  // nothing done with the event, throw an error on the transport layer if
  // needed
  // can't have more than one tag in the reply, not supported yet.
  switch (G_io_seproxyhal_spi_buffer[0]) {
  case SEPROXYHAL_TAG_FINGER_EVENT:
    UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
    break;
  // power off if long push, else pass to the application callback if any
  case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: // for Nano S
    UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
    break;

  case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
    UX_DISPLAYED_EVENT({});
    break;
  case SEPROXYHAL_TAG_TICKER_EVENT:
    UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer,
    {
       // only allow display when not locked of overlayed by an OS UX.
      if (UX_ALLOWED ) {
        UX_REDISPLAY();
      }
    });
    break;
    // other events are propagated to the UX just in case
  default:
    UX_DEFAULT_EVENT();
    break;

  }

  // close the event if not done previously (by a display or whatever)
  if (!io_seproxyhal_spi_is_status_sent()) {
    io_seproxyhal_general_status();
  }
  // command has been processed, DO NOT reset the current APDU transport
  return 1;
}

