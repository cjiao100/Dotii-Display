#pragma once
/* Transport-neutral DTU1/DTZ1 stream reassembly.
 *
 * Wire format (shared with bridge/dtu_protocol.py):
 *   "DTU1" | u32 LE body length | u32 LE CRC-32 (zlib) of body | UTF-8 JSON body
 *   "DTZ1" | u32 LE body length | u32 LE CRC-32 (zlib) of body | body
 *            where body = u32 LE inflated length | zlib stream of the JSON
 *
 * The parser has no ESP-IDF dependency so it can be unit-tested on the host.
 * It never parses JSON; complete frames are handed to a callback that owns
 * the body buffer afterwards. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DTU_MAGIC_PLAIN "DTU1"
#define DTU_MAGIC_ZLIB "DTZ1"

typedef void *(*dtu_alloc_fn)(size_t size);
typedef void (*dtu_free_fn)(void *pointer);
/* Called with ownership of body (allocated with alloc, length + 1 bytes,
   NUL-terminated). Return false to have the parser free it. */
typedef bool (*dtu_frame_fn)(void *context, uint8_t *body, size_t length, bool compressed);

typedef enum {
    DTU_STATE_MAGIC = 0,
    DTU_STATE_HEADER,
    DTU_STATE_BODY,
} dtu_state_t;

typedef struct {
    dtu_state_t state;
    uint8_t magic[4];
    unsigned magic_length;
    uint8_t header[8];
    unsigned header_length;
    bool compressed;
    uint8_t *body;
    size_t expected;
    size_t received;
    uint32_t expected_crc;
    uint32_t running_crc;
    size_t max_frame;
    dtu_alloc_fn alloc;
    dtu_free_fn free;
    dtu_frame_fn on_frame;
    void *context;
    uint32_t frames;
    uint32_t crc_errors;
    uint32_t size_errors;
    uint32_t alloc_errors;
    uint32_t rejected;
} dtu_stream_t;

uint32_t dtu_crc32_update(uint32_t crc, const uint8_t *data, size_t length);
static inline uint32_t dtu_crc32(const uint8_t *data, size_t length)
{
    return dtu_crc32_update(0, data, length);
}

void dtu_stream_init(dtu_stream_t *stream, size_t max_frame, dtu_alloc_fn alloc, dtu_free_fn free_fn,
                     dtu_frame_fn on_frame, void *context);
/* Drop any partial frame and resynchronise on the next magic. */
void dtu_stream_reset(dtu_stream_t *stream);
/* Feed bytes; returns the number of complete frames delivered. */
unsigned dtu_stream_feed(dtu_stream_t *stream, const uint8_t *data, size_t length);
bool dtu_stream_idle(const dtu_stream_t *stream);
/* Encode a DTU header for body; out must hold 12 bytes. */
void dtu_encode_header(uint8_t out[12], bool compressed, const uint8_t *body, size_t length);
