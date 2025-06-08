#include "pico/stdlib.h"
#include "mac_radio.h"
#include "hal_gpio.h"
#include "pico_bootsel_button.h"

/*
 This example demonstrates how to use the macRadio module in automatic role mode, the device will alternate
 between central and peripheral mode trying to find a peer to connect to and comunicate with.

 NOTE: Using this code with a radio might not be legal. Allways follow your local radio spectrum regulations.

 This example should be used two with PICO's with a RFM69 radio.

 The example works best if a second LED is connected GPIO 9 to show when packets arrive. The PICO on board
 LED is used to show connection state.

 Note: The example uses the broadcast address to enable flashing multiple devices without changing addresses.
       all devices will receive the packets sent. (Excluding the sender)
       Setting a unique address to each device is recommended.
*/

// Configure device address
#define RADIO_MY_ADDR         (0x01)
#define RADIO_TX_BUFFER_SIZE  (128 + C_BUFFER_ARRAY_OVERHEAD) 
#define PKT_LED               (13)

#ifndef LOG
#define LOG(f_, ...) printf((f_), ##__VA_ARGS__)
#endif

uint8_t msg[] = {'H', 'e', 'l', 'l', 'o', '!'};

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
    bool             packet_available;

    // LED management
    bool led_state;
    bool test_led_state;
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

void buttonEventCb(picoBootSelButtonInterface_t *interface, picoBootSelButtonEvent_t event) {
    mainCtx_t* inst = CONTAINER_OF(interface, mainCtx_t, btn_interface);

    // Check if the packet is available
    if (!inst->packet_available) {
        // Just ignore the button press if not available
        return;
    }

    // Write the new message to the packet buffer
    int32_t res = cBufferPrepend(inst->packet.pkt_buffer, msg, sizeof(msg));
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

// This callback gets called when connection state changes
int32_t connStateCb(macRadioInterface_t *interface, macRadioConn_t conn_state) {
    mainCtx_t* inst = CONTAINER_OF(interface, mainCtx_t, mac_interface);

    // Check the updated connection state
    switch(conn_state.conn_state) {
        case MAC_RADIO_CONNECTED:
            LOG("CONNECTED\n");
            inst->led_state = true;
            break;
        case MAC_RADIO_DISCONNECTED:
            LOG("DISCONNECTED\n");
            inst->led_state = false;
            break;
        default:
            return MAC_RADIO_CB_ERROR;
    }

    inst->packet.conn_id = conn_state.conn_id;

    pico_set_led(inst->led_state);
    return MAC_RADIO_CB_SUCCESS;
}

// This callback gets called when a packet has been successfully sent, or errors occured
int32_t packageSent(macRadioInterface_t *interface, macRadioPacket_t *pkt, macRadioErr_t result) {
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
        // This is ok I think
        LOG("SEND FAILED\n");
        return MAC_RADIO_CB_SUCCESS;
    }

    // All other errors are potentially fatal, this will trigger a fail result in process.
    if (result != MAC_RADIO_SUCCESS) {
        return result;
    }

    return MAC_RADIO_CB_SUCCESS;
}

// This callback gets called when a new packet has arrived
int32_t packageCallback(macRadioInterface_t *interface, macRadioPacket_t *packet) {
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

    LOG("%i bytes received.\n", result);

    // Print out payload
    LOG("Payload: ");
    for (int32_t i = 0; i < result; i++) {
        LOG("%c", cBufferReadByte(packet->pkt_buffer));
    }
    LOG("\n\n");
    return MAC_RADIO_CB_SUCCESS;
}

// This callback gets called when a packet has been acked, timed out or other response.
static int32_t respCb(macRadioInterface_t *interface, macRadioPacket_t *packet, macRadioPacket_t *response, macRadioErr_t result) {
    mainCtx_t* inst = CONTAINER_OF(interface, mainCtx_t, mac_interface);

    if (result == MAC_RADIO_PKT_TIMEOUT) {
        LOG("Packet timeout %i\n", result);
        result = MAC_RADIO_SUCCESS;
    } else if (result != MAC_RADIO_SUCCESS) {
       // Any error hear is potentially fatal, this will trigger a fail result in process.
        LOG("Packet failed %i\n", result);
        return result;
    }

    inst->packet_available = true;

    return MAC_RADIO_CB_SUCCESS;
}

int main() {
    stdio_init_all(); // To be able to use printf
    // Initialize the gpio module to make sure all modules can use it
    halGpioInit();
    int rc = pico_led_init();
    hard_assert(rc == PICO_OK);

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
        .my_address = RADIO_MY_ADDR,
    };

    // Initialize the radio
    res = macRadioInit(&main_instance.mac_radio, mac_config, &main_instance.mac_interface);

    if (res != MAC_RADIO_SUCCESS) {
        LOG("RADIO INIT FAILED!\n");
        device_error();
    }

    // Init the LED states
    main_instance.led_state      = false;
    main_instance.test_led_state = false;

    // Create a message
    if ((res = cBufferInit(&main_instance.tx_buffer, main_instance.tx_package_buf, RADIO_TX_BUFFER_SIZE)) != C_BUFFER_SUCCESS) {
        LOG("RADIO INIT FAILED!\n");
        device_error();
    }

    // Prepare packet
    main_instance.packet.pkt_buffer = &main_instance.tx_buffer;
    main_instance.packet.pkt_type   = MAC_RADIO_BROADCAST_PKT;
    main_instance.packet.conn_id    = 0; // TODO temporary
    main_instance.packet_available = true;

    // Configure the radio mode
    res = macRadioSetAutoMode(&main_instance.mac_radio);

    if (res != MAC_RADIO_SUCCESS) {
        LOG("Set Mode Failed\n");
        device_error();
    }

    // Process forever
    while (true) {
        // Process the radio
        res = macRadioProcess(&main_instance.mac_radio);
        if (res != MAC_RADIO_SUCCESS) {
            LOG("RADIO PROCESS FAILED! %i\n", res);
            device_error();
        }

        // Process the button
        res = picoBootSelButtonProcess(&main_instance.boot_button);
        if (res != PICO_BOOTSEL_BTN_SUCCESS) {
            LOG("BUTTON PROCESS FAILED!\n");
            device_error();
        }
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
