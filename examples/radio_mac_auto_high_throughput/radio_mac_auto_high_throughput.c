#include "pico/stdlib.h"
#include "mac_radio.h"
#include "hal_gpio.h"
#include "logger.h"
#include "pico_bootsel_button.h"

/*
 This example demonstrates how to use the macRadio module in automatic role mode, the device will alternate
 between central and peripheral mode trying to find a peer to connect to and comunicate with.

 The button activates/deactivates continous transmission of data to the other device with maximum throughput

 NOTE: Using this code with a radio might not be legal. Allways follow your local radio spectrum regulations.

 This example should be used with two PICO's with a RFM69 radio.

 The example works best if a second LED is connected GPIO 9 to show when packets arrive. The PICO on board
 LED is used to show connection state.

 Note: The example uses the broadcast address to enable flashing multiple devices without changing addresses.
       all devices will receive the packets sent. (Excluding the sender)
       Setting a unique address to each device is recommended.
*/

// Configure device address
#define RADIO_MY_ADDR             (0x01)
#define RADIO_TX_BUFFER_SIZE      (255 + C_BUFFER_ARRAY_OVERHEAD) 
#define PKT_LED                   (13)
#define PRINT_THROUGHPUT_INTERVAL (25000)

// Forward declaration of radio_log
void radio_log(const char *format, ...);

// Main logging using DMA logger
#ifndef LOG
#define LOG(f_, ...) radio_log((f_), ##__VA_ARGS__)
#endif

// Short message
//static uint8_t msg[] = {'H', 'e', 'l', 'l', 'o', '!'};

// Large message
static uint8_t msg[] = {
    '1', ',', ' ', '2', ',', ' ', '3', ',', ' ', '4', ',', ' ', '5', ',', ' ',
    '6', ',', ' ', '7', ',', ' ', '8', ',', ' ', '9', ',', ' ', '1', '0', ',', ' ',
    '1', '1', ',', ' ', '1', '2', ',', ' ', '1', '3', ',', ' ', '1', '4', ',', ' ',
    '1', '5', ',', ' ', '1', '6', ',', ' ', '1', '7', ',', ' ', '1', '8', ',', ' ',
    '1', '9', ',', ' ', '2', '0', ',', ' ', '2', '1', ',', ' ', '2', '2', ',', ' ',
    '2', '3', ',', ' ', '2', '4', ',', ' ', '2', '5', ',', ' ', '2', '6', ',', ' ',
    '2', '7', ',', ' ', '2', '8', ',', ' ', '2', '9', ',', ' ', '3', '0',
    '3', '1', ',', ' ', '3', '2'};

typedef struct mainCtx {
    // Radio
    macRadio_t          mac_radio;
    macRadioInterface_t mac_interface;

    // Button
    picoBootSelButton_t          boot_button;
    picoBootSelButtonInterface_t btn_interface;

    // Tx packet
    macRadioPacket_t packet;
    uint8_t          tx_package_buf[RADIO_TX_BUFFER_SIZE];
    cBuffer_t        tx_buffer;
    bool             packet_available; // Used to keep track of when a packet is in active transfer
    bool             send_packets; // Used to keep track of packet transfer active

    // LED management
    bool led_state;
    bool test_led_state;

    // Connection tracking
    uint32_t active_conn_ids[MAC_RADIO_MAX_NUM_CONNECTIONS]; // Store active connection IDs
    uint32_t active_connections; // Count of active connections

    // Measure througphut and processor utilization
    uint64_t last_packet_timestamp_us;
    float    ema_bitrate_bps;
    float    radio_time_percentage;
} mainCtx_t;

// Local variables
static mainCtx_t main_instance = {0};

// Declare and define local functions
static void device_error();

// Perform initialisation
int pico_led_init(void) {
#if defined(PICO_DEFAULT_LED_PIN)
    // A device like Pico that uses a GPIO for the LED will define PICO_DEFAULT_LED_PIN
    // so we can use normal GPIO functionality to turn the led on and off
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    gpio_init(PKT_LED);
    gpio_set_dir(PKT_LED, GPIO_OUT);
    return PICO_OK;
#endif
}

// Turn the led on or off
void set_pkt_led(bool led_on) {
    // Just set the GPIO on or off
    gpio_put(PKT_LED, led_on);
}

// Turn the led on or off
void pico_set_led(bool led_on) {
#if defined(PICO_DEFAULT_LED_PIN)
    // Just set the GPIO on or off
    gpio_put(PICO_DEFAULT_LED_PIN, led_on);
#endif
}

static void sendPackage(mainCtx_t* inst) {
    if (!inst->packet_available) {
        return;
    }

    int32_t res = cBufferClear(inst->packet.pkt_buffer);
    if (res != C_BUFFER_SUCCESS) {
        LOG("RADIO SEND FAILED! %i\n", res);
        device_error();
    }

    res = cBufferPrepend(inst->packet.pkt_buffer, msg, sizeof(msg));
    if (res != sizeof(msg)) {
        LOG("RADIO SEND FAILED! %i\n", res);
        device_error();
    }

    res = macRadioSendOnConnection(&inst->mac_radio, &inst->packet);

    if (res == MAC_RADIO_NO_CONN_ERROR) {
        // This is fine, just means that we try to send without an active connection
        return;
    }

    if (res != MAC_RADIO_SUCCESS) {
        LOG("RADIO SEND FAILED! %i\n", res);
        device_error();
    }

    inst->packet_available = false;
}

static void calculateBitrate(mainCtx_t* inst, uint32_t num_bytes)
{
    // Choose a smoothing factor: 0.0 < ALPHA <= 1.0.
    // Higher ALPHA -> less smoothing (reacts faster).
    // Lower ALPHA -> more smoothing (reacts slower).
    const float ALPHA = 0.05;

    uint64_t now_us = to_us_since_boot(get_absolute_time());

    // If this is truly the first packet, just record the time and skip
    if (inst->last_packet_timestamp_us == 0) {
        inst->last_packet_timestamp_us = now_us;
        inst->ema_bitrate_bps = 0.0;
        return;
    }

    // Time in seconds since last packet
    float delta_sec = (float)(now_us - inst->last_packet_timestamp_us) / 1000000.0;

    // Update the timestamp for next round
    inst->last_packet_timestamp_us = now_us;

    // Guard against zero or negative intervals
    if (delta_sec <= 0.0) {
        return;
    }

    // Convert the new packet size to bits
    float bits = (float)num_bytes;

    // Instantaneous rate = bits / elapsed time
    float instantaneous_bps = bits / delta_sec;

    // Exponential moving average update
    inst->ema_bitrate_bps = ALPHA * instantaneous_bps + (1.0 - ALPHA) * inst->ema_bitrate_bps;
}

static void buttonEventCb(picoBootSelButtonInterface_t *interface, picoBootSelButtonEvent_t event) {
    if (interface == NULL) {
        LOG("INTERFACE IS NULL!!\n");
        device_error();
    }

    mainCtx_t* inst = CONTAINER_OF(interface, mainCtx_t, btn_interface);

    // Start or stop sending packets
    inst->send_packets = !inst->send_packets;
    if (inst->send_packets) {
        sendPackage(inst);
    }
}

// This callback gets called when connection state changes
int32_t connStateCb(macRadioInterface_t *interface, macRadioConn_t conn_state) {
    if (interface == NULL) {
        LOG("INTERFACE IS NULL!!\n");
        device_error();
    }

    mainCtx_t* inst = CONTAINER_OF(interface, mainCtx_t, mac_interface);

    // Check the updated connection state
    switch(conn_state.conn_state) {
        case MAC_RADIO_CONNECTED:
            LOG("CONNECTED (conn_id: %d)\n", conn_state.conn_id);

            inst->packet.conn_id = conn_state.conn_id;

            // Add connection if not already tracked
            bool already_tracked = false;
            for (uint32_t i = 0; i < inst->active_connections; i++) {
                if (inst->active_conn_ids[i] == conn_state.conn_id) {
                    already_tracked = true;
                    break;
                }
            }

            if (!already_tracked && inst->active_connections < MAC_RADIO_MAX_NUM_CONNECTIONS) {
                inst->active_conn_ids[inst->active_connections] = conn_state.conn_id;
                inst->active_connections++;
            }

            // Start/keep sending packets on connections
            if (inst->send_packets) {
                sendPackage(inst);
            }
            break;

        case MAC_RADIO_DISCONNECTED:
            LOG("DISCONNECTED (conn_id: %d)\n", conn_state.conn_id);

            // Remove connection from tracking
            for (uint32_t i = 0; i < inst->active_connections; i++) {
                if (inst->active_conn_ids[i] == conn_state.conn_id) {
                    // Shift remaining connections down
                    for (uint32_t j = i; j < inst->active_connections - 1; j++) {
                        inst->active_conn_ids[j] = inst->active_conn_ids[j + 1];
                    }
                    inst->active_connections--;
                    break;
                }
            }
            break;

        default:
            return MAC_RADIO_CB_ERROR;
    }

    // Only turn LED on if we have at least one active connection
    inst->led_state = (inst->active_connections > 0);
    pico_set_led(inst->led_state);

    return MAC_RADIO_CB_SUCCESS;
}

// This callback gets called when a packet has been successfully sent, or errors occured
int32_t packageSent(macRadioInterface_t *interface, macRadioPacket_t *pkt, macRadioErr_t result) {
    if (pkt == NULL || interface == NULL) {
        LOG("PACKET OR INTERFACE IS NULL!\n");
        device_error();
    }

    mainCtx_t* inst = CONTAINER_OF(interface, mainCtx_t, mac_interface);

    // Check if the packet sent is a reliable packet, those are occupied until a response or timeout
    if (inst->packet.pkt_type != MAC_RADIO_RELIABLE_PKT) {
        inst->packet_available = true;
    }

    // Check the result, if it was just a send fail, we ignore it and keep running.
    // This could happen if a connection was lost before the packet was sent.
    if (result == PHY_RADIO_SEND_FAIL) {
        // An error will allways release the packet
        inst->packet_available = true;
        LOG("SEND FAILED\n");

        // Try to resend
        if (inst->send_packets) {
            sendPackage(inst);
        }

        return MAC_RADIO_CB_SUCCESS;
    } else if (result != MAC_RADIO_SUCCESS) {
        // Fatal error
        LOG("SEND FAILED %i\n", result);
        device_error();
    }

    return MAC_RADIO_CB_SUCCESS;
}

// This callback gets called when a new packet has arrived
int32_t packageCallback(macRadioInterface_t *interface, macRadioPacket_t *packet) {
    if (packet == NULL || interface == NULL) {
        LOG("PACKET OR INTERFACE IS NULL!\n");
        device_error();
    }

    mainCtx_t* inst = CONTAINER_OF(interface, mainCtx_t, mac_interface);

    inst->test_led_state = !inst->test_led_state;
    set_pkt_led(inst->test_led_state);

    int32_t result = cBufferAvailableForRead(packet->pkt_buffer);

    // Check the result
    if (result < MAC_RADIO_SUCCESS) {
       // Any error hear is potentially fatal, this will trigger a fail result in process.
        LOG("Invalid packet received %i.\n", result);
        return result;
    }

    /* 
    // Print packet size and contents to console
    LOG("%i bytes received.\n", result);

    LOG("Payload: ");
    for (int32_t i = 0; i < result; i++) {
        LOG("%c", cBufferReadByte(packet->pkt_buffer));
    }
    LOG("\n\n");
    */

    calculateBitrate(inst, result);

    return MAC_RADIO_CB_SUCCESS;
}

// This callback gets called when a packet has been acked, timed out or other response.
static int32_t respCb(macRadioInterface_t *interface, macRadioPacket_t *packet, macRadioPacket_t *response, macRadioErr_t result) {
    if (interface == NULL || packet == NULL) {
        LOG("INTERFACE OR PACKET IS NULL! %u %u\n", interface, packet);
        device_error();
    }

    mainCtx_t* inst = CONTAINER_OF(interface, mainCtx_t, mac_interface);

    if (result == MAC_RADIO_PKT_TIMEOUT) {
        LOG("Packet timeout %i\n", result);
        result = MAC_RADIO_SUCCESS;
    } else if (result != MAC_RADIO_SUCCESS) {
       // Any error hear is potentially fatal, this will trigger a fail result in process.
        LOG("Packet failed %i\n", result);
        return result;
    }

    // Packet send
    inst->packet_available = true;

    // Send the next package
    if (inst->send_packets) {
        sendPackage(inst);
    }

    return MAC_RADIO_CB_SUCCESS;
}

// Override the weak radio_log function to use DMA logger
void radio_log(const char *format, ...) {
    va_list args;
    va_start(args, format);

    char buffer[256];
    vsnprintf(buffer, sizeof(buffer), format, args);
    loggerPrintf("%s", buffer);

    va_end(args);
}

int main() {
    stdio_init_all(); // To be able to use printf
    // Initialize the gpio module to make sure all modules can use it
    halGpioInit();
    int rc = pico_led_init();
    hard_assert(rc == PICO_OK);

    // Initialize the DMA-based non-blocking logger
    if (loggerInit() != 0) {
        // Fallback to USB stdio if logger fails
        printf("Logger init failed!\n");
    }

    // Initializ main parameters
    main_instance.packet_available = true;
    main_instance.send_packets     = false;
    main_instance.led_state      = false;
    main_instance.test_led_state = false;

    // Initialize throughput measurement variables
    main_instance.last_packet_timestamp_us = 0;
    main_instance.ema_bitrate_bps          = 0.0;
    main_instance.radio_time_percentage    = 0.0;

    // Prepare bootsel button
    main_instance.btn_interface.event_cb = buttonEventCb;
    int32_t res = picoBootSelButtonInit(&main_instance.boot_button, &main_instance.btn_interface);
    if (res != PICO_BOOTSEL_BTN_SUCCESS) {
        LOG("BUTTON INIT FAILED!\n");
        device_error();
    }

    // Populate callbacks
    main_instance.mac_interface.pkt_cb  = packageCallback;
    main_instance.mac_interface.sent_cb = packageSent;
    main_instance.mac_interface.conn_cb = connStateCb;
    main_instance.mac_interface.resp_cb = respCb;

    macRadioConfig_t mac_config = {
        .my_address     = RADIO_MY_ADDR,
        // Each device supports N connections, and then we need one slot for this device
        .num_data_slots = MAC_RADIO_MAX_NUM_CONNECTIONS + 1,
    };

    // Initialize the radio
    res = macRadioInit(&main_instance.mac_radio, mac_config, &main_instance.mac_interface);

    if (res != MAC_RADIO_SUCCESS) {
        LOG("RADIO INIT FAILED!\n");
        device_error();
    }

    // Create a radio message buffer
    if ((res = cBufferInit(&main_instance.tx_buffer, main_instance.tx_package_buf, RADIO_TX_BUFFER_SIZE)) != C_BUFFER_SUCCESS) {
        LOG("RADIO INIT FAILED!\n");
        device_error();
    }

    // Prepare packet
    main_instance.packet.pkt_buffer = &main_instance.tx_buffer;
    main_instance.packet.pkt_type   = MAC_RADIO_RELIABLE_PKT;
    main_instance.packet.conn_id    = 0; // TODO temporary

    // Configure the radio mode
    res = macRadioSetAutoMode(&main_instance.mac_radio);

    if (res != MAC_RADIO_SUCCESS) {
        LOG("Set Mode Failed\n");
        device_error();
    }

    uint64_t loop_elapsed = 0;
    uint32_t count = 0;
    // Process forever
    while (true) {
        // Mark the start of this loop
        uint64_t loop_start_us = to_us_since_boot(get_absolute_time());

        // Check if the radio has pending events
        bool has_event = (macRadioEventInQueue(&main_instance.mac_radio) > MAC_RADIO_SUCCESS);

        // Track how long we spent inside macRadioProcess()
        uint64_t radio_elapsed_us = 0;

        if (has_event) {
            // Time before calling macRadioProcess
            uint64_t radio_start_us = to_us_since_boot(get_absolute_time());

            int32_t res = macRadioProcess(&main_instance.mac_radio);
            if (res != MAC_RADIO_SUCCESS) {
                LOG("RADIO PROCESS FAILED! %i\n", res);
                device_error();
            }

            // Time after returning from macRadioProcess
            uint64_t radio_end_us = to_us_since_boot(get_absolute_time());
            radio_elapsed_us       = radio_end_us - radio_start_us;
        }

        // Process the button
        res = picoBootSelButtonProcess(&main_instance.boot_button);
        if (res != PICO_BOOTSEL_BTN_SUCCESS) {
            LOG("BUTTON PROCESS FAILED!\n");
            device_error();
        }

        // Mark the end of the loop iteration
        uint64_t loop_end_us   = to_us_since_boot(get_absolute_time());
        loop_elapsed  += loop_end_us - loop_start_us;

        // === Compute instantaneous ratio & update EMA ===
        if (loop_elapsed > 0 && radio_elapsed_us > 0) {
            // ratio for *this loop iteration* in percent
            float instant_ratio = ((float)radio_elapsed_us / (float)loop_elapsed) * 100.0;

            // pick a smoothing factor
            float ALPHA = 0.01;  // tune as needed

            // Update the exponential average
            main_instance.radio_time_percentage = ALPHA * instant_ratio + (1.0 - ALPHA) * main_instance.radio_time_percentage;
            loop_elapsed  = 0;
        }

        if (count > PRINT_THROUGHPUT_INTERVAL) {
            LOG("D: %.1f Bps, P: %.1f%%\n", main_instance.ema_bitrate_bps, main_instance.radio_time_percentage);
            count = 0;
        }

        count++;
    }
}

static void device_error() {
    // Forever blink fast
    while (true) {
        pico_set_led(true);
        sleep_ms(100);
        pico_set_led(false);
        sleep_ms(100);
    }
}
