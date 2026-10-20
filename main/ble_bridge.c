#include "ble_bridge.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "connectivity.h"
#include "device_config.h"
#include "dtu_stream.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "host/ble_store.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "store/config/ble_store_config.h"

#define RX_MAX 1024
#define RESPONSE_MAX 384

/* Data channel. One ATT write or notification carries
   [type u8][seq u8][payload]. DATA payloads are a DTU1/DTZ1 byte stream, so
   chunk boundaries are independent of frame boundaries. */
#define DATA_PACKET_MAX 524           /* ATT MTU 527 - 3 */
#define DATA_HEADER 2
#define DATA_MAX_FRAME (64 * 1024)    /* body bytes, compressed or plain */
#define DATA_FRAME_QUEUE 3
#define CREDIT_EVERY_PACKETS 4
#define PKT_DATA 0x01
#define PKT_RESET 0x02
#define PKT_CREDIT 0x03
#define PKT_NAK 0x04
#define PKT_BENCH 0x10
#define PKT_BENCH_RESET 0x11
#define PREFERRED_TX_OCTETS 251
#define PREFERRED_TX_TIME 2120
/* Apple Accessory Design Guidelines: interval min >= 15 ms and a multiple of
   15 ms, max >= min + 15 ms, latency <= 30, supervision timeout 6-18 s. */
#define CONN_ITVL_MIN 12   /* 15 ms in 1.25 ms units */
#define CONN_ITVL_MAX 24   /* 30 ms */
#define CONN_LATENCY 0
#define CONN_TIMEOUT 600   /* 6 s in 10 ms units */
#define LINK_TUNE_DELAY_MS 1000

static const char *TAG = "ble_bridge";
static uint8_t s_own_addr_type;
static uint16_t s_response_handle;
static uint8_t s_rx[RX_MAX + 1];
static size_t s_rx_expected;
static size_t s_rx_length;
static uint32_t s_rx_crc;
static char s_response[RESPONSE_MAX] = "{\"ok\":true,\"state\":\"ready\"}";
static bool s_prepared;
static bool s_started;

typedef struct {
    uint16_t mtu;
    uint16_t dle_tx_octets;
    uint16_t dle_tx_time;
    uint16_t dle_rx_octets;
    uint16_t dle_rx_time;
    int dle_request_rc;
    int conn_update_rc;
    int phy_request_rc;
    int mtu_request_rc;
    bool encrypted;
    bool bonded;
    uint32_t rx_packets;
    uint32_t rx_bytes;
    uint32_t seq_gaps;
    uint32_t queue_drops;
    uint32_t credits_sent;
    uint32_t credit_failures;
    uint32_t tx_frames;
    uint32_t tx_packets;
    uint32_t tx_retries;
    uint32_t tx_failures;
    uint32_t bench_bytes;
    uint32_t bench_packets;
    uint32_t bench_gaps;
    int64_t bench_first_us;
    int64_t bench_last_us;
} data_stats_t;

static volatile uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static volatile uint32_t s_session;
static uint32_t s_session_counter;
static uint16_t s_data_tx_handle;
static volatile bool s_tx_subscribed;
static bool s_rx_seq_valid;
static uint8_t s_rx_seq_expected;
static uint32_t s_rx_total;
static unsigned s_packets_since_credit;
static uint8_t s_tx_seq;
static dtu_stream_t s_stream;
static QueueHandle_t s_frames;
static SemaphoreHandle_t s_tx_lock;
static struct ble_npl_callout s_link_callout;
static data_stats_t s_stats;
/* Only the host task touches the RX scratch buffer and only the TX lock owner
   touches the TX one; both stay out of internal RAM. */
EXT_RAM_BSS_ATTR static uint8_t s_data_rx_packet[DATA_PACKET_MAX];
EXT_RAM_BSS_ATTR static uint8_t s_data_tx_packet[DATA_PACKET_MAX];

void ble_store_config_init(void);

/* 7b4e0001-4db4-4c72-a729-ea5187241a43 */
static const ble_uuid128_t SERVICE_UUID = BLE_UUID128_INIT(
    0x43, 0x1a, 0x24, 0x87, 0x51, 0xea, 0x29, 0xa7,
    0x72, 0x4c, 0xb4, 0x4d, 0x01, 0x00, 0x4e, 0x7b);
static const ble_uuid128_t COMMAND_UUID = BLE_UUID128_INIT(
    0x43, 0x1a, 0x24, 0x87, 0x51, 0xea, 0x29, 0xa7,
    0x72, 0x4c, 0xb4, 0x4d, 0x02, 0x00, 0x4e, 0x7b);
static const ble_uuid128_t RESPONSE_UUID = BLE_UUID128_INIT(
    0x43, 0x1a, 0x24, 0x87, 0x51, 0xea, 0x29, 0xa7,
    0x72, 0x4c, 0xb4, 0x4d, 0x03, 0x00, 0x4e, 0x7b);
static const ble_uuid128_t STATUS_UUID = BLE_UUID128_INIT(
    0x43, 0x1a, 0x24, 0x87, 0x51, 0xea, 0x29, 0xa7,
    0x72, 0x4c, 0xb4, 0x4d, 0x04, 0x00, 0x4e, 0x7b);
/* 7b4e0005: Mac -> Dotii data stream (write / write without response, ENC). */
static const ble_uuid128_t DATA_RX_UUID = BLE_UUID128_INIT(
    0x43, 0x1a, 0x24, 0x87, 0x51, 0xea, 0x29, 0xa7,
    0x72, 0x4c, 0xb4, 0x4d, 0x05, 0x00, 0x4e, 0x7b);
/* 7b4e0006: Dotii -> Mac data stream and credits (notify, ENC). */
static const ble_uuid128_t DATA_TX_UUID = BLE_UUID128_INIT(
    0x43, 0x1a, 0x24, 0x87, 0x51, 0xea, 0x29, 0xa7,
    0x72, 0x4c, 0xb4, 0x4d, 0x06, 0x00, 0x4e, 0x7b);

static uint32_t crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xffffffffU;
    for (size_t index = 0; index < length; index++) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

static bool secure_equal(const char *left, const char *right)
{
    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    uint8_t difference = (uint8_t)(left_len ^ right_len);
    size_t length = left_len > right_len ? left_len : right_len;
    for (size_t index = 0; index < length; index++) {
        uint8_t a = index < left_len ? (uint8_t)left[index] : 0;
        uint8_t b = index < right_len ? (uint8_t)right[index] : 0;
        difference |= a ^ b;
    }
    return difference == 0;
}

static void set_response(const char *json)
{
    strlcpy(s_response, json, sizeof(s_response));
    if (s_response_handle != 0) ble_gatts_chr_updated(s_response_handle);
}

static void delayed_restart(void *argument)
{
    (void)argument;
    esp_restart();
}

static void schedule_restart(void)
{
    const esp_timer_create_args_t args = {.callback = delayed_restart, .name = "ble_restart"};
    esp_timer_handle_t timer;
    if (esp_timer_create(&args, &timer) == ESP_OK) {
        (void)esp_timer_start_once(timer, 1500000);
    }
}

static bool copy_required_string(cJSON *root, const char *key, char *target, size_t capacity, bool allow_empty)
{
    cJSON *value = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!cJSON_IsString(value) || value->valuestring == NULL) return false;
    size_t length = strlen(value->valuestring);
    if (length >= capacity || (!allow_empty && length == 0)) return false;
    strlcpy(target, value->valuestring, capacity);
    return true;
}

static void apply_configuration(void)
{
    s_rx[s_rx_length] = '\0';
    cJSON *root = cJSON_ParseWithLength((const char *)s_rx, s_rx_length);
    if (!cJSON_IsObject(root)) {
        set_response("{\"ok\":false,\"error\":\"invalid_json\"}");
        cJSON_Delete(root);
        return;
    }
    cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "v");
    cJSON *operation = cJSON_GetObjectItemCaseSensitive(root, "op");
    cJSON *auth = cJSON_GetObjectItemCaseSensitive(root, "auth");
    const device_config_values_t *current = device_config_get();
    if (!cJSON_IsNumber(version) || version->valueint != 1 ||
        !cJSON_IsString(operation) || strcmp(operation->valuestring, "configure") != 0 ||
        !cJSON_IsString(auth) ||
        (current->provisioned && !secure_equal(auth->valuestring, current->bridge_token))) {
        set_response("{\"ok\":false,\"error\":\"unauthorized\"}");
        cJSON_Delete(root);
        return;
    }
    device_config_values_t next = {0};
    bool valid = copy_required_string(root, "ssid", next.wifi_ssid, sizeof(next.wifi_ssid), false) &&
                 copy_required_string(root, "password", next.wifi_password, sizeof(next.wifi_password), true) &&
                 copy_required_string(root, "bridge_url", next.bridge_url, sizeof(next.bridge_url), false) &&
                 copy_required_string(root, "bridge_token", next.bridge_token, sizeof(next.bridge_token), false) &&
                 (strncmp(next.bridge_url, "http://", 7) == 0 || strncmp(next.bridge_url, "https://", 8) == 0) &&
                 strlen(next.bridge_token) >= 16;
    if (!valid) {
        set_response("{\"ok\":false,\"error\":\"invalid_config\"}");
        cJSON_Delete(root);
        return;
    }
    esp_err_t error = device_config_save(&next);
    cJSON_Delete(root);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "Unable to save Bluetooth configuration: %s", esp_err_to_name(error));
        set_response("{\"ok\":false,\"error\":\"storage_failed\"}");
        return;
    }
    ESP_LOGI(TAG, "Bluetooth provisioning accepted; restarting to apply configuration");
    set_response("{\"ok\":true,\"state\":\"restarting\"}");
    schedule_restart();
}

static int handle_command(struct os_mbuf *om)
{
    uint8_t buffer[256];
    uint16_t length = 0;
    if (ble_hs_mbuf_to_flat(om, buffer, sizeof(buffer), &length) != 0 || length < 1) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    if (buffer[0] == 1) {
        if (length != 7) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        size_t expected = (size_t)buffer[1] | ((size_t)buffer[2] << 8);
        if (expected == 0 || expected > RX_MAX) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        s_rx_expected = expected;
        s_rx_length = 0;
        s_rx_crc = (uint32_t)buffer[3] | ((uint32_t)buffer[4] << 8) |
                   ((uint32_t)buffer[5] << 16) | ((uint32_t)buffer[6] << 24);
        set_response("{\"ok\":true,\"state\":\"receiving\"}");
        return 0;
    }
    if (buffer[0] == 2) {
        if (s_rx_expected == 0 || s_rx_length + length - 1 > s_rx_expected) {
            return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        }
        memcpy(s_rx + s_rx_length, buffer + 1, length - 1);
        s_rx_length += length - 1;
        return 0;
    }
    if (buffer[0] == 3) {
        if (length != 1 || s_rx_length != s_rx_expected || crc32(s_rx, s_rx_length) != s_rx_crc) {
            set_response("{\"ok\":false,\"error\":\"checksum_failed\"}");
            s_rx_expected = 0;
            return 0;
        }
        apply_configuration();
        s_rx_expected = 0;
        return 0;
    }
    return BLE_ATT_ERR_REQ_NOT_SUPPORTED;
}

static void *frame_alloc(size_t size)
{
    return heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

static bool deliver_frame(void *context, uint8_t *body, size_t length, bool compressed)
{
    (void)context;
    ble_frame_t frame = {.body = body, .length = length, .compressed = compressed, .session = s_session};
    if (s_frames == NULL || xQueueSend(s_frames, &frame, 0) != pdTRUE) {
        s_stats.queue_drops++;
        return false;
    }
    return true;
}

static void reset_data_channel(void)
{
    dtu_stream_reset(&s_stream);
    s_rx_seq_valid = false;
    s_rx_seq_expected = 0;
    s_rx_total = 0;
    s_packets_since_credit = 0;
}

static void reset_bench(void)
{
    s_stats.bench_bytes = 0;
    s_stats.bench_packets = 0;
    s_stats.bench_gaps = 0;
    s_stats.bench_first_us = 0;
    s_stats.bench_last_us = 0;
}

/* Host task only: never block; a lost credit is superseded by the next one. */
static bool notify_now(uint16_t conn_handle, const uint8_t *data, size_t length)
{
    if (s_data_tx_handle == 0 || !s_tx_subscribed) return false;
    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, length);
    if (om == NULL) return false;
    return ble_gatts_notify_custom(conn_handle, s_data_tx_handle, om) == 0;
}

static void send_credit(uint16_t conn_handle)
{
    uint8_t packet[8] = {PKT_CREDIT, 0,
                         (uint8_t)s_rx_total, (uint8_t)(s_rx_total >> 8),
                         (uint8_t)(s_rx_total >> 16), (uint8_t)(s_rx_total >> 24),
                         s_rx_seq_expected,
                         (uint8_t)(s_frames != NULL ? uxQueueSpacesAvailable(s_frames) : 0)};
    if (notify_now(conn_handle, packet, sizeof(packet))) s_stats.credits_sent++;
    else s_stats.credit_failures++;
    s_packets_since_credit = 0;
}

static void send_nak(uint16_t conn_handle, uint8_t expected, uint8_t received)
{
    uint8_t packet[4] = {PKT_NAK, 0, expected, received};
    (void)notify_now(conn_handle, packet, sizeof(packet));
}

/* Runs in the NimBLE host task (4 KB stack): copy and count only, never parse
   JSON or decompress here. */
static int handle_data_write(uint16_t conn_handle, struct os_mbuf *om)
{
    uint16_t length = OS_MBUF_PKTLEN(om);
    if (length < DATA_HEADER || length > sizeof(s_data_rx_packet)) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    if (ble_hs_mbuf_to_flat(om, s_data_rx_packet, sizeof(s_data_rx_packet), &length) != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    const uint8_t type = s_data_rx_packet[0];
    const uint8_t seq = s_data_rx_packet[1];
    if (type == PKT_RESET) {
        reset_data_channel();
        send_credit(conn_handle);
        return 0;
    }
    if (type == PKT_BENCH_RESET) {
        reset_bench();
        reset_data_channel();
        send_credit(conn_handle);
        return 0;
    }
    if (type != PKT_DATA && type != PKT_BENCH) return BLE_ATT_ERR_REQ_NOT_SUPPORTED;

    if (s_rx_seq_valid && seq != s_rx_seq_expected) {
        s_stats.seq_gaps++;
        if (type == PKT_BENCH) s_stats.bench_gaps++;
        else dtu_stream_reset(&s_stream);
        send_nak(conn_handle, s_rx_seq_expected, seq);
    }
    s_rx_seq_valid = true;
    s_rx_seq_expected = (uint8_t)(seq + 1);
    const size_t payload = length - DATA_HEADER;
    s_rx_total += payload;
    s_stats.rx_packets++;
    s_stats.rx_bytes += payload;
    unsigned frames = 0;
    if (type == PKT_DATA) {
        frames = dtu_stream_feed(&s_stream, s_data_rx_packet + DATA_HEADER, payload);
    } else {
        const int64_t now = esp_timer_get_time();
        if (s_stats.bench_packets == 0) s_stats.bench_first_us = now;
        s_stats.bench_last_us = now;
        s_stats.bench_packets++;
        s_stats.bench_bytes += payload;
    }
    if (++s_packets_since_credit >= CREDIT_EVERY_PACKETS || frames > 0) send_credit(conn_handle);
    return 0;
}

uint32_t ble_bridge_session(void)
{
    return s_conn_handle != BLE_HS_CONN_HANDLE_NONE ? s_session : 0;
}

bool ble_bridge_session_ready(uint32_t session)
{
    return session != 0 && session == ble_bridge_session() && s_tx_subscribed && s_stats.encrypted;
}

bool ble_bridge_receive(ble_frame_t *frame)
{
    return s_frames != NULL && xQueueReceive(s_frames, frame, 0) == pdTRUE;
}

void ble_bridge_frame_free(ble_frame_t *frame)
{
    if (frame == NULL) return;
    heap_caps_free(frame->body);
    frame->body = NULL;
    frame->length = 0;
}

static bool notify_blocking(uint16_t conn_handle, const uint8_t *data, size_t length)
{
    for (unsigned attempt = 0; attempt < 200; attempt++) {
        if (conn_handle != s_conn_handle || !s_tx_subscribed) return false;
        struct os_mbuf *om = ble_hs_mbuf_from_flat(data, length);
        int rc = om == NULL ? BLE_HS_ENOMEM : ble_gatts_notify_custom(conn_handle, s_data_tx_handle, om);
        if (rc == 0) {
            s_stats.tx_packets++;
            return true;
        }
        if (rc != BLE_HS_ENOMEM && rc != BLE_HS_EBUSY) break;
        s_stats.tx_retries++;
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    s_stats.tx_failures++;
    return false;
}

bool ble_bridge_send_json(uint32_t session, cJSON *message)
{
    if (!ble_bridge_session_ready(session) || s_tx_lock == NULL) return false;
    char *body = cJSON_PrintUnformatted(message);
    if (body == NULL) return false;
    const size_t length = strlen(body);
    uint8_t header[12];
    dtu_encode_header(header, false, (const uint8_t *)body, length);
    bool ok = xSemaphoreTake(s_tx_lock, pdMS_TO_TICKS(2000)) == pdTRUE;
    if (ok) {
        const uint16_t conn_handle = s_conn_handle;
        uint16_t mtu = ble_att_mtu(conn_handle);
        if (mtu < 23) mtu = 23;
        size_t chunk = (size_t)mtu - 3 - DATA_HEADER;
        if (chunk > sizeof(s_data_tx_packet) - DATA_HEADER) chunk = sizeof(s_data_tx_packet) - DATA_HEADER;
        const size_t total = sizeof(header) + length;
        for (size_t offset = 0; ok && offset < total;) {
            const size_t take = total - offset < chunk ? total - offset : chunk;
            for (size_t index = 0; index < take; index++) {
                const size_t position = offset + index;
                s_data_tx_packet[DATA_HEADER + index] = position < sizeof(header) ?
                    header[position] : (uint8_t)body[position - sizeof(header)];
            }
            s_data_tx_packet[0] = PKT_DATA;
            s_data_tx_packet[1] = s_tx_seq++;
            ok = session == s_session && notify_blocking(conn_handle, s_data_tx_packet, DATA_HEADER + take);
            offset += take;
        }
        if (ok) s_stats.tx_frames++;
        xSemaphoreGive(s_tx_lock);
    }
    cJSON_free(body);
    return ok;
}

static void add_heap(cJSON *parent, const char *name, uint32_t caps)
{
    cJSON *heap = cJSON_AddObjectToObject(parent, name);
    if (heap == NULL) return;
    cJSON_AddNumberToObject(heap, "free", heap_caps_get_free_size(caps));
    cJSON_AddNumberToObject(heap, "largest", heap_caps_get_largest_free_block(caps));
    cJSON_AddNumberToObject(heap, "minimum", heap_caps_get_minimum_free_size(caps));
}

void ble_bridge_fill_diag(cJSON *object)
{
    cJSON *ble = cJSON_AddObjectToObject(object, "ble");
    if (ble != NULL) {
        const uint16_t conn_handle = s_conn_handle;
        const bool connected = conn_handle != BLE_HS_CONN_HANDLE_NONE;
        cJSON_AddBoolToObject(ble, "connected", connected);
        cJSON_AddBoolToObject(ble, "subscribed", s_tx_subscribed);
        cJSON_AddNumberToObject(ble, "preferred_mtu", ble_att_preferred_mtu());
        if (connected) {
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(conn_handle, &desc) == 0) {
                cJSON_AddNumberToObject(ble, "conn_interval_ms", desc.conn_itvl * 1.25);
                cJSON_AddNumberToObject(ble, "conn_latency", desc.conn_latency);
                cJSON_AddNumberToObject(ble, "supervision_timeout_ms", desc.supervision_timeout * 10);
                cJSON_AddBoolToObject(ble, "encrypted", desc.sec_state.encrypted);
                cJSON_AddBoolToObject(ble, "bonded", desc.sec_state.bonded);
                cJSON_AddNumberToObject(ble, "key_size", desc.sec_state.key_size);
            }
            cJSON_AddNumberToObject(ble, "mtu", ble_att_mtu(conn_handle));
            uint8_t tx_phy = 0, rx_phy = 0;
            if (ble_gap_read_le_phy(conn_handle, &tx_phy, &rx_phy) == 0) {
                cJSON_AddNumberToObject(ble, "tx_phy", tx_phy);
                cJSON_AddNumberToObject(ble, "rx_phy", rx_phy);
            }
        }
        cJSON_AddNumberToObject(ble, "dle_tx_octets", s_stats.dle_tx_octets);
        cJSON_AddNumberToObject(ble, "dle_tx_time", s_stats.dle_tx_time);
        cJSON_AddNumberToObject(ble, "dle_rx_octets", s_stats.dle_rx_octets);
        cJSON_AddNumberToObject(ble, "dle_rx_time", s_stats.dle_rx_time);
        cJSON_AddNumberToObject(ble, "dle_request_rc", s_stats.dle_request_rc);
        cJSON_AddNumberToObject(ble, "conn_update_rc", s_stats.conn_update_rc);
        cJSON_AddNumberToObject(ble, "phy_request_rc", s_stats.phy_request_rc);
        cJSON_AddNumberToObject(ble, "mtu_request_rc", s_stats.mtu_request_rc);
        cJSON_AddNumberToObject(ble, "rx_packets", s_stats.rx_packets);
        cJSON_AddNumberToObject(ble, "rx_bytes", s_stats.rx_bytes);
        cJSON_AddNumberToObject(ble, "seq_gaps", s_stats.seq_gaps);
        cJSON_AddNumberToObject(ble, "frames", s_stream.frames);
        cJSON_AddNumberToObject(ble, "crc_errors", s_stream.crc_errors);
        cJSON_AddNumberToObject(ble, "size_errors", s_stream.size_errors);
        cJSON_AddNumberToObject(ble, "alloc_errors", s_stream.alloc_errors);
        cJSON_AddNumberToObject(ble, "queue_drops", s_stats.queue_drops);
        cJSON_AddNumberToObject(ble, "credits_sent", s_stats.credits_sent);
        cJSON_AddNumberToObject(ble, "credit_failures", s_stats.credit_failures);
        cJSON_AddNumberToObject(ble, "tx_frames", s_stats.tx_frames);
        cJSON_AddNumberToObject(ble, "tx_packets", s_stats.tx_packets);
        cJSON_AddNumberToObject(ble, "tx_retries", s_stats.tx_retries);
        cJSON_AddNumberToObject(ble, "tx_failures", s_stats.tx_failures);
        cJSON *bench = cJSON_AddObjectToObject(ble, "bench");
        if (bench != NULL) {
            const int64_t elapsed = s_stats.bench_last_us - s_stats.bench_first_us;
            cJSON_AddNumberToObject(bench, "bytes", s_stats.bench_bytes);
            cJSON_AddNumberToObject(bench, "packets", s_stats.bench_packets);
            cJSON_AddNumberToObject(bench, "gaps", s_stats.bench_gaps);
            cJSON_AddNumberToObject(bench, "elapsed_ms", (double)elapsed / 1000.0);
            cJSON_AddNumberToObject(bench, "bytes_per_s",
                                    elapsed > 0 ? (double)s_stats.bench_bytes * 1000000.0 / (double)elapsed : 0);
        }
    }
    cJSON *heap = cJSON_AddObjectToObject(object, "heap");
    if (heap != NULL) {
        add_heap(heap, "internal", MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        add_heap(heap, "spiram", MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
}

static int gatt_access(uint16_t conn_handle, uint16_t attr_handle,
                       struct ble_gatt_access_ctxt *ctxt, void *argument)
{
    (void)attr_handle;
    (void)argument;
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR && ble_uuid_cmp(ctxt->chr->uuid, &DATA_RX_UUID.u) == 0) {
        return handle_data_write(conn_handle, ctxt->om);
    }
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR && ble_uuid_cmp(ctxt->chr->uuid, &COMMAND_UUID.u) == 0) {
        return handle_command(ctxt->om);
    }
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR && ble_uuid_cmp(ctxt->chr->uuid, &RESPONSE_UUID.u) == 0) {
        return os_mbuf_append(ctxt->om, s_response, strlen(s_response)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR && ble_uuid_cmp(ctxt->chr->uuid, &STATUS_UUID.u) == 0) {
        char bridge[64];
        connectivity_get_bridge_summary(bridge, sizeof(bridge));
        char status[RESPONSE_MAX];
        snprintf(status, sizeof(status),
                 "{\"v\":1,\"name\":\"Dotii\",\"firmware\":\"%s\",\"provisioned\":%s,\"wifi\":%s,\"bridge\":\"%s\",\"sync\":1}",
                 esp_app_get_description()->version,
                 device_config_get()->provisioned ? "true" : "false",
                 connectivity_is_wifi_connected() ? "true" : "false", bridge);
        return os_mbuf_append(ctxt->om, status, strlen(status)) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static const struct ble_gatt_svc_def SERVICES[] = {{
    .type = BLE_GATT_SVC_TYPE_PRIMARY,
    .uuid = &SERVICE_UUID.u,
    .characteristics = (struct ble_gatt_chr_def[]){{
        .uuid = &COMMAND_UUID.u,
        .access_cb = gatt_access,
        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
    }, {
        .uuid = &RESPONSE_UUID.u,
        .access_cb = gatt_access,
        .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &s_response_handle,
    }, {
        .uuid = &STATUS_UUID.u,
        .access_cb = gatt_access,
        .flags = BLE_GATT_CHR_F_READ,
    }, {
        .uuid = &DATA_RX_UUID.u,
        .access_cb = gatt_access,
        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC,
    }, {
        .uuid = &DATA_TX_UUID.u,
        .access_cb = gatt_access,
        /* NOTIFY_INDICATE_ENC makes the CCCD write require an encrypted link. */
        .flags = BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_NOTIFY_INDICATE_ENC,
        .val_handle = &s_data_tx_handle,
    }, {0}}
}, {0}};

static int gap_event(struct ble_gap_event *event, void *argument);

static void advertise(void)
{
    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)ble_svc_gap_device_name();
    fields.name_len = strlen((char *)fields.name);
    fields.name_is_complete = 1;
    fields.uuids128 = (ble_uuid128_t *)&SERVICE_UUID;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;
    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "Unable to set advertising fields: %d", rc);
        return;
    }
    struct ble_gap_adv_params params = {0};
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &params, gap_event, NULL);
    if (rc != 0) ESP_LOGE(TAG, "Unable to advertise: %d", rc);
}

#if MYNEWT_VAL(BLE_GATTC)
static int mtu_exchanged(uint16_t conn_handle, const struct ble_gatt_error *error, uint16_t mtu, void *argument)
{
    (void)conn_handle;
    (void)argument;
    if (error != NULL && error->status == 0) s_stats.mtu = mtu;
    return 0;
}
#endif

static void request_data_length(uint16_t conn_handle)
{
    s_stats.dle_request_rc = ble_gap_set_data_len(conn_handle, PREFERRED_TX_OCTETS, PREFERRED_TX_TIME);
    if (s_stats.dle_request_rc != 0) ESP_LOGW(TAG, "Data length request failed: %d", s_stats.dle_request_rc);
}

/* Runs on the NimBLE host task a moment after connecting so the central has
   finished its own MTU exchange and service discovery first. */
static void tune_link(struct ble_npl_event *event)
{
    (void)event;
    const uint16_t conn_handle = s_conn_handle;
    if (conn_handle == BLE_HS_CONN_HANDLE_NONE) return;
    const struct ble_gap_upd_params params = {
        .itvl_min = CONN_ITVL_MIN,
        .itvl_max = CONN_ITVL_MAX,
        .latency = CONN_LATENCY,
        .supervision_timeout = CONN_TIMEOUT,
        .min_ce_len = 0,
        .max_ce_len = 0,
    };
    s_stats.conn_update_rc = ble_gap_update_params(conn_handle, &params);
    request_data_length(conn_handle);
    s_stats.phy_request_rc = ble_gap_set_prefered_le_phy(conn_handle, BLE_GAP_LE_PHY_2M_MASK,
                                                         BLE_GAP_LE_PHY_2M_MASK, BLE_GAP_LE_PHY_CODED_ANY);
#if MYNEWT_VAL(BLE_GATTC)
    s_stats.mtu_request_rc = ble_gattc_exchange_mtu(conn_handle, mtu_exchanged, NULL);
#else
    /* The GATT client role is compiled out; macOS initiates the exchange. */
    s_stats.mtu_request_rc = BLE_HS_ENOTSUP;
#endif
    ESP_LOGI(TAG, "Link tuning requested: conn=%d dle=%d phy=%d mtu=%d",
             s_stats.conn_update_rc, s_stats.dle_request_rc, s_stats.phy_request_rc, s_stats.mtu_request_rc);
}

static void session_begin(uint16_t conn_handle)
{
    s_conn_handle = conn_handle;
    if (++s_session_counter == 0) s_session_counter = 1;
    s_session = s_session_counter;
    s_tx_subscribed = false;
    s_tx_seq = 0;
    const uint32_t queue_drops = s_stats.queue_drops;
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.queue_drops = queue_drops;
    s_stats.mtu = ble_att_mtu(conn_handle);
    reset_data_channel();
    ble_npl_callout_reset(&s_link_callout, ble_npl_time_ms_to_ticks32(LINK_TUNE_DELAY_MS));
}

static void session_end(void)
{
    ble_npl_callout_stop(&s_link_callout);
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_tx_subscribed = false;
    s_stats.encrypted = false;
    reset_data_channel();
}

static int gap_event(struct ble_gap_event *event, void *argument)
{
    (void)argument;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            ESP_LOGI(TAG, "Bluetooth bridge connected");
            session_begin(event->connect.conn_handle);
        } else {
            advertise();
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "Bluetooth bridge disconnected: %d", event->disconnect.reason);
        session_end();
        advertise();
        return 0;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        advertise();
        return 0;
    case BLE_GAP_EVENT_SUBSCRIBE:
        if (s_data_tx_handle != 0 && event->subscribe.attr_handle == s_data_tx_handle) {
            s_tx_subscribed = event->subscribe.cur_notify;
            ESP_LOGI(TAG, "Bluetooth data channel %s", s_tx_subscribed ? "subscribed" : "unsubscribed");
        }
        return 0;
    case BLE_GAP_EVENT_MTU:
        s_stats.mtu = event->mtu.value;
        ESP_LOGI(TAG, "Bluetooth MTU updated: %d", event->mtu.value);
        return 0;
    case BLE_GAP_EVENT_ENC_CHANGE:
        ESP_LOGI(TAG, "Bluetooth encryption changed: %d", event->enc_change.status);
        if (event->enc_change.status == 0) {
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(event->enc_change.conn_handle, &desc) == 0) {
                s_stats.encrypted = desc.sec_state.encrypted;
                s_stats.bonded = desc.sec_state.bonded;
            }
            /* Some centrals reset or reject DLE across (re-)encryption. */
            request_data_length(event->enc_change.conn_handle);
        }
        return 0;
    case BLE_GAP_EVENT_CONN_UPDATE:
        if (event->conn_update.status == 0) {
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(event->conn_update.conn_handle, &desc) == 0) {
                ESP_LOGI(TAG, "Connection params: interval=%u x1.25ms latency=%u timeout=%u x10ms",
                         desc.conn_itvl, desc.conn_latency, desc.supervision_timeout);
            }
        }
        return 0;
    case BLE_GAP_EVENT_CONN_UPDATE_REQ:
        return 0;
    case BLE_GAP_EVENT_DATA_LEN_CHG:
        s_stats.dle_tx_octets = event->data_len_chg.max_tx_octets;
        s_stats.dle_tx_time = event->data_len_chg.max_tx_time;
        s_stats.dle_rx_octets = event->data_len_chg.max_rx_octets;
        s_stats.dle_rx_time = event->data_len_chg.max_rx_time;
        ESP_LOGI(TAG, "Data length: tx=%u rx=%u", event->data_len_chg.max_tx_octets,
                 event->data_len_chg.max_rx_octets);
        return 0;
    case BLE_GAP_EVENT_PHY_UPDATE_COMPLETE:
        ESP_LOGI(TAG, "PHY update: status=%d tx=%d rx=%d", event->phy_updated.status,
                 event->phy_updated.tx_phy, event->phy_updated.rx_phy);
        return 0;
    default:
        return 0;
    }
}

static void on_sync(void)
{
    int rc = ble_hs_util_ensure_addr(0);
    if (rc == 0) rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "Unable to select Bluetooth address: %d", rc);
        return;
    }
    advertise();
}

static void host_task(void *argument)
{
    (void)argument;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t ble_bridge_prepare(void)
{
    if (s_prepared) return ESP_OK;
    esp_err_t error = nimble_port_init();
    if (error != ESP_OK) return error;
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_svc_gap_init();
    ble_svc_gatt_init();
    int rc = ble_gatts_count_cfg(SERVICES);
    if (rc == 0) rc = ble_gatts_add_svcs(SERVICES);
    if (rc == 0) rc = ble_svc_gap_device_name_set("Dotii");
    if (rc != 0) return ESP_FAIL;
    ble_store_config_init();
    s_frames = xQueueCreate(DATA_FRAME_QUEUE, sizeof(ble_frame_t));
    s_tx_lock = xSemaphoreCreateMutex();
    if (s_frames == NULL || s_tx_lock == NULL) return ESP_ERR_NO_MEM;
    dtu_stream_init(&s_stream, DATA_MAX_FRAME, frame_alloc, heap_caps_free, deliver_frame, NULL);
    ble_npl_callout_init(&s_link_callout, nimble_port_get_dflt_eventq(), tune_link, NULL);
    s_prepared = true;
    ESP_LOGI(TAG, "Bluetooth controller reserved");
    return ESP_OK;
}

esp_err_t ble_bridge_start(void)
{
    if (!s_prepared) return ESP_ERR_INVALID_STATE;
    if (s_started) return ESP_OK;
    nimble_port_freertos_init(host_task);
    s_started = true;
    ESP_LOGI(TAG, "Bluetooth bridge started");
    return ESP_OK;
}

esp_err_t ble_bridge_clear_bonds(void)
{
    if (!s_prepared) return ESP_ERR_INVALID_STATE;
    int rc = ble_store_clear();
    if (rc != 0) {
        ESP_LOGW(TAG, "Unable to clear Bluetooth bonds: %d", rc);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Bluetooth bonds cleared");
    return ESP_OK;
}
