#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"
#include "esp_err.h"

/* A complete DTU1/DTZ1 frame received on the BLE data characteristic.
   body lives in PSRAM and must be released with ble_bridge_frame_free(). */
typedef struct {
    uint8_t *body;
    size_t length;
    bool compressed;
    uint32_t session;
} ble_frame_t;

esp_err_t ble_bridge_prepare(void);
esp_err_t ble_bridge_start(void);
esp_err_t ble_bridge_clear_bonds(void);

/* Data channel (phase 1 sync). The session id changes on every connection;
   0 means no central is connected. */
uint32_t ble_bridge_session(void);
bool ble_bridge_session_ready(uint32_t session);
bool ble_bridge_receive(ble_frame_t *frame);
void ble_bridge_frame_free(ble_frame_t *frame);
/* Encode message as a DTU1 frame and notify it on DATA_TX. Must not be called
   from the NimBLE host task. Returns false when the session is gone. */
bool ble_bridge_send_json(uint32_t session, cJSON *message);
/* Link, heap and throughput-bench diagnostics (phase 0). */
void ble_bridge_fill_diag(cJSON *object);
