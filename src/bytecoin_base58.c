#include "os.h"
#include "bytecoin_base58.h"
#include "bytecoin_ledger_api.h"

static const char alphabet[]                = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const size_t encoded_block_sizes[]   = { 0, 2, 3, 5, 6, 7, 9, 10, 11 };

#define ALPHABET_SIZE            (sizeof(alphabet) - 1)
#define FULL_BLOCK_SIZE          8
#define FULL_ENCODED_BLOCK_SIZE  11

static
uint64_t uint64_be_from_bytes(const uint8_t* buf, size_t len)
{
    uint64_t var = 0;
    for (size_t i = 0; i < len; ++i)
        var |= ((uint64_t)buf[i]) << ((len - i - 1) * 8);
    return var;
}

static
void encode_block_base58(const uint8_t* block, size_t size, char* result)
{
    uint64_t num = uint64_be_from_bytes(block, size);
    for (size_t i = encoded_block_sizes[size]; i --> 0; )
    {
        const uint64_t remainder = num % ALPHABET_SIZE;
        num /= ALPHABET_SIZE;
        result[i] = alphabet[remainder];
    }
}

size_t encode_base58(const uint8_t* data, size_t data_len, char* result, size_t result_len)
{
    const size_t full_block_count = data_len / FULL_BLOCK_SIZE;
    const size_t last_block_size  = data_len % FULL_BLOCK_SIZE;
    const size_t needed_result_len = FULL_ENCODED_BLOCK_SIZE * full_block_count + encoded_block_sizes[last_block_size];
    if (needed_result_len > result_len)
        THROW(SW_WRONG_LENGTH);
    for (size_t i = 0; i < full_block_count; ++i)
        encode_block_base58(data + i * FULL_BLOCK_SIZE, FULL_BLOCK_SIZE, result + i * FULL_ENCODED_BLOCK_SIZE);
    if (last_block_size > 0)
        encode_block_base58(data + full_block_count * FULL_BLOCK_SIZE, last_block_size, result + full_block_count * FULL_ENCODED_BLOCK_SIZE);
    return needed_result_len;
}
