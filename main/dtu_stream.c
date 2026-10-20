#include "dtu_stream.h"

#include <string.h>

uint32_t dtu_crc32_update(uint32_t crc, const uint8_t *data, size_t length)
{
    crc = ~crc;
    for (size_t index = 0; index < length; index++) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

static uint32_t read_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static void write_le32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)(value >> 16);
    data[3] = (uint8_t)(value >> 24);
}

void dtu_stream_init(dtu_stream_t *stream, size_t max_frame, dtu_alloc_fn alloc, dtu_free_fn free_fn,
                     dtu_frame_fn on_frame, void *context)
{
    memset(stream, 0, sizeof(*stream));
    stream->max_frame = max_frame;
    stream->alloc = alloc;
    stream->free = free_fn;
    stream->on_frame = on_frame;
    stream->context = context;
}

void dtu_stream_reset(dtu_stream_t *stream)
{
    if (stream->body != NULL) stream->free(stream->body);
    stream->body = NULL;
    stream->state = DTU_STATE_MAGIC;
    stream->magic_length = 0;
    stream->header_length = 0;
    stream->expected = 0;
    stream->received = 0;
}

bool dtu_stream_idle(const dtu_stream_t *stream)
{
    return stream->state == DTU_STATE_MAGIC && stream->magic_length == 0;
}

/* Accept a byte into the magic matcher. Both magics share the "DT" prefix
   and the trailing "1", so a mismatch can restart on a fresh "D". */
static void feed_magic(dtu_stream_t *stream, uint8_t byte)
{
    static const char plain[] = DTU_MAGIC_PLAIN;
    static const char zlib[] = DTU_MAGIC_ZLIB;
    unsigned position = stream->magic_length;
    bool match_plain = position < 4 && byte == (uint8_t)plain[position] &&
                       (position < 2 || memcmp(stream->magic, plain, position) == 0);
    bool match_zlib = position < 4 && byte == (uint8_t)zlib[position] &&
                      (position < 2 || memcmp(stream->magic, zlib, position) == 0);
    if (match_plain || match_zlib) {
        stream->magic[stream->magic_length++] = byte;
    } else {
        stream->magic_length = 0;
        if (byte == (uint8_t)'D') stream->magic[stream->magic_length++] = byte;
        return;
    }
    if (stream->magic_length == 4) {
        stream->compressed = memcmp(stream->magic, zlib, 4) == 0;
        stream->state = DTU_STATE_HEADER;
        stream->header_length = 0;
        stream->magic_length = 0;
    }
}

static void begin_body(dtu_stream_t *stream)
{
    size_t length = read_le32(stream->header);
    stream->expected_crc = read_le32(stream->header + 4);
    size_t minimum = stream->compressed ? 5 : 1;
    if (length < minimum || length > stream->max_frame) {
        stream->size_errors++;
        dtu_stream_reset(stream);
        return;
    }
    stream->body = stream->alloc(length + 1);
    if (stream->body == NULL) {
        stream->alloc_errors++;
        dtu_stream_reset(stream);
        return;
    }
    stream->expected = length;
    stream->received = 0;
    stream->running_crc = 0;
    stream->state = DTU_STATE_BODY;
}

unsigned dtu_stream_feed(dtu_stream_t *stream, const uint8_t *data, size_t length)
{
    unsigned delivered = 0;
    size_t index = 0;
    while (index < length) {
        if (stream->state == DTU_STATE_MAGIC) {
            feed_magic(stream, data[index++]);
        } else if (stream->state == DTU_STATE_HEADER) {
            stream->header[stream->header_length++] = data[index++];
            if (stream->header_length == sizeof(stream->header)) begin_body(stream);
        } else {
            size_t take = stream->expected - stream->received;
            if (take > length - index) take = length - index;
            memcpy(stream->body + stream->received, data + index, take);
            stream->running_crc = dtu_crc32_update(stream->running_crc, data + index, take);
            stream->received += take;
            index += take;
            if (stream->received == stream->expected) {
                uint8_t *body = stream->body;
                size_t body_length = stream->expected;
                bool compressed = stream->compressed;
                stream->body = NULL;
                stream->state = DTU_STATE_MAGIC;
                stream->magic_length = 0;
                if (stream->running_crc != stream->expected_crc) {
                    stream->crc_errors++;
                    stream->free(body);
                    continue;
                }
                body[body_length] = 0;
                stream->frames++;
                delivered++;
                if (!stream->on_frame(stream->context, body, body_length, compressed)) {
                    stream->rejected++;
                    stream->free(body);
                }
            }
        }
    }
    return delivered;
}

void dtu_encode_header(uint8_t out[12], bool compressed, const uint8_t *body, size_t length)
{
    memcpy(out, compressed ? DTU_MAGIC_ZLIB : DTU_MAGIC_PLAIN, 4);
    write_le32(out + 4, (uint32_t)length);
    write_le32(out + 8, dtu_crc32(body, length));
}
