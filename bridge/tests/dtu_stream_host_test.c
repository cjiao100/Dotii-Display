/* Host harness for main/dtu_stream.c, driven by bridge/tests/test_firmware_dtu_stream.py.
 * Reads a byte stream on stdin, feeds it in varying chunk sizes and prints
 * one line per delivered frame plus the parser counters. */
#include <stdio.h>
#include <stdlib.h>

#include "dtu_stream.h"

static bool on_frame(void *context, uint8_t *body, size_t length, bool compressed)
{
    (void)context;
    printf("F %d %zu %08x %d\n", compressed ? 1 : 0, length, dtu_crc32(body, length), body[length] == 0);
    free(body);
    return true;
}

int main(int argc, char **argv)
{
    size_t max_frame = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 4096;
    static uint8_t input[1 << 20];
    size_t total = fread(input, 1, sizeof(input), stdin);
    dtu_stream_t stream;
    dtu_stream_init(&stream, max_frame, malloc, free, on_frame, NULL);
    size_t offset = 0;
    unsigned step = 0;
    while (offset < total) {
        size_t chunk = 1 + (step++ * 7) % 61;
        if (chunk > total - offset) chunk = total - offset;
        dtu_stream_feed(&stream, input + offset, chunk);
        offset += chunk;
    }
    printf("C %u %u %u %u %d\n", stream.frames, stream.crc_errors, stream.size_errors, stream.alloc_errors,
           dtu_stream_idle(&stream));
    return 0;
}
