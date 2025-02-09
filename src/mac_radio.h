/**
 * @file:       mac_radio.h
 * @author:     Lucas Wennerholm <lucas.wennerholm@gmail.com>
 * @brief:      Header file for the radio mac layer
 * @details:    This layer manages connections, device roles, acknowlaged packets, stream packets
 *
 * @license: MIT License
 *
 * Copyright (c) 2024 Lucas Wennerholm
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#ifndef MAC_RADIO_H
#define MAC_RADIO_H
#include "pico/stdlib.h"
#include "phy_radio.h"
#include "c_buffer.h"
#include "static_pool.h"
#include "static_map.h"

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, member)	(type *)((char *)(ptr) - offsetof(type,member))
#endif

// Packet size and overhead
#define MAC_RADIO_PKT_TYPE_SIZE   1
#define MAC_RADIO_MSG_ID_SIZE     1
#define MAC_RADIO_OVERHEAD_SIZE   (MAC_RADIO_PKT_TYPE_SIZE + MAC_RADIO_MSG_ID_SIZE)
#define MAC_RADIO_MAX_PACKET_SIZE (PHY_RADIO_MAX_PACKET_SIZE - MAC_RADIO_OVERHEAD_SIZE)

// Internal packets
#define MAC_RADIO_INTERNAL_MSG_SIZE        (MAC_RADIO_OVERHEAD_SIZE)
#define MAC_RADIO_INTERNAL_MSG_BUFFER_SIZE (MAC_RADIO_INTERNAL_MSG_SIZE + PHY_RADIO_TOTAL_OVERHEAD_SIZE + C_BUFFER_ARRAY_OVERHEAD)

// Packet management
#define MAC_RADIO_POOL_SIZE                5
#define MAC_RADIO_MAP_SIZE                 5

// Max Number of missed keep alive from peripheral before a disconnect is triggered
#define MAC_RADIO_SYNC_TIMEOUT (PHY_RADIO_SYNC_TIMEOUT) // Use the same as Peripheral timeout

typedef enum {
    MAC_RADIO_SUCCESS,
    MAC_RADIO_NULL_ERROR    = -30001,
    MAC_RADIO_INVALID_ERROR = -30002,
    MAC_RADIO_POOL_ERROR    = -30003,
    MAC_RADIO_MAP_ERROR     = -30004,
    MAC_RADIO_BUFFER_ERROR  = -30009,
    MAC_RADIO_NO_CONN_ERROR = -30010,
    MAC_RADIO_PKT_TIMEOUT   = -30011,
    MAC_RADIO_UNKONWN_ACK   = -30012,
} macRadioErr_t;

typedef enum {
    MAC_RADIO_CB_SUCCESS,
    MAC_RADIO_CB_ERROR = -30050,
} macRadioCbRetVal_t;

typedef struct macRadioInterface macRadioInterface_t; // Forward declararion of upstream interface
typedef struct macRadioPacket macRadioPacket_t; // Forward declararion of mac Packet
typedef struct macRadioConn macRadioConn_t; // Forward declararion of mac Packet

// This callback gets called when a new incomming packet has arrived
// The macRadioPacket_t *packet parameter is the pointer to the new incomming data
typedef int32_t (*macRadioPacketCb_t)(macRadioInterface_t *interface, macRadioPacket_t *packet);

// This callback gets called when a packet has been sent
// The macRadioPacket_t *packet parameter is the pointer to the original packet sent
typedef int32_t (*macRadioSentCb_t)(macRadioInterface_t *interface, macRadioPacket_t *packet, macRadioErr_t result);

// This callback gets called on connection events
typedef int32_t (*macRadioConnCb_t)(macRadioInterface_t *interface, macRadioConn_t connection);

// This callback gets called when a response to a packet was received
// If the response was a simple ACK the response pointer will be NULL but the result MAC_RADIO_SUCCESS.
// If the response contains data the response will be pointer will contain the data
// The macRadioPacket_t *packet parameter is the pointer to the original packet sent
typedef int32_t (*macRadioRespCb_t)(macRadioInterface_t *interface, macRadioPacket_t *packet, macRadioPacket_t *response, macRadioErr_t result);

typedef enum {
    MAC_RADIO_SYNC_PKT = 1, // TODO this is never used, remove?
    MAC_RADIO_SYNC_ACK_PKT,
    MAC_RADIO_ACK_PKT,
    MAC_RADIO_KEEP_ALIVE_PKT,
    MAC_RADIO_RELIABLE_PKT,
    MAC_RADIO_STREAM_PKT,
    MAC_RADIO_CLOSE_PKT,
} macRadioPacketType_t;

typedef enum {
    MAC_RADIO_DISCONNECTED,
    MAC_RADIO_CONNECTING,
    MAC_RADIO_CONNECTED,
} macRadioConnState_t;

typedef enum {
    MAC_RADIO_IDLE,
    MAC_RADIO_CENTRAL,
    MAC_RADIO_PERIPHERAL,
    MAC_RADIO_AUTO_MODE,
} macRadioMode_t;

// Definition of packet
struct macRadioPacket {
    uint32_t   conn_id;
    uint32_t   pkt_type;
    cBuffer_t *pkt_buffer;
};

// Definition of interface
struct macRadioInterface {
    macRadioPacketCb_t pkt_cb;
    macRadioSentCb_t   sent_cb;
    macRadioConnCb_t   conn_cb;
    macRadioRespCb_t   resp_cb;
};

typedef struct {
    uint8_t my_address;
} macRadioConfig_t;

struct macRadioConn {
    macRadioConnState_t conn_state;
    uint32_t            conn_id;
};

typedef struct {
    phyRadioPacket_t  packet;
    macRadioPacket_t *mac_pkt;
    bool              internal;
    uint8_t           msg_id;
    staticPoolItem_t  node;
} macRadioPktPoolItem_t;

typedef struct {
    uint8_t           _msg_array[MAC_RADIO_INTERNAL_MSG_BUFFER_SIZE];
    cBuffer_t         msg_buf;
    macRadioPacket_t  mac_pkt;
    staticPoolItem_t  node;
} macRadioBufferPoolItem_t;

typedef struct {
    macRadioPacket_t *mac_pkt;
    uint32_t          ttl;
    bool              sent;
    bool              internal;
    staticMapItem_t   node;
} macRadioPktTrackItem_t;

typedef struct {
    // Mode and configuration
    macRadioConfig_t current_config;
    macRadioMode_t   mode;

    // Connection management
    uint8_t        central_addr;
    struct {
        uint32_t last_heard; // Last time we heard from a device
        uint32_t conn_state;
        uint32_t my_tx_slot;
        uint32_t target_addr;
    } connections;

    // Internal Packet management
    macRadioBufferPoolItem_t _buffer_pkt_pool[MAC_RADIO_POOL_SIZE];
    staticPoolList_t         _buffer_pool_array[MAC_RADIO_POOL_SIZE];
    staticPool_t             buffer_packet_pool;
    staticMap_t              track_map;
    staticMapItem_t*         _map_array[MAC_RADIO_MAP_SIZE];
    macRadioPktTrackItem_t   _track_map_array[MAC_RADIO_MAP_SIZE];

    // External Packet management
    uint8_t            msg_id;
    macRadioPktPoolItem_t _pkt_pool[MAC_RADIO_POOL_SIZE];
    staticPoolList_t      _pool_array[MAC_RADIO_POOL_SIZE];
    staticPool_t          packet_pool;

    // PHY radio
    phyRadio_t phy_instance;
    phyRadioInterface_t phy_interface;

    // Callback management
    macRadioInterface_t *interface;
} macRadio_t;

/**
 * Initialize this module.
 * Input: Pointer to mac radio instance
 * Input: Pointer to interface
 * Returns: macRadioErr_t
 */
int32_t macRadioInit(macRadio_t *inst, macRadioConfig_t config, macRadioInterface_t *interface);

/**
 * Process the mac radio
 * Input: macRadio instance
 * Returns: macRadioErr_t
 */
int32_t macRadioProcess(macRadio_t *inst);

/**
 * Set the radio in auto mode to scan for available central devices or
 * take the central role if no central was detected.
 * Input: Pointer to mac radio instance
 * Returns: macRadioErr_t
 */
int32_t macRadioSetAutoMode(macRadio_t *inst);

/**
 * Set the radio in central mode and allow incomming connections.
 * Input: Pointer to mac radio instance
 * Returns: macRadioErr_t
 */
int32_t macRadioSetCentralMode(macRadio_t *inst);

/**
 * Set the radio in peripheral mode. Search for a central device and connect to it if found.
 * Input: Pointer to mac radio instance
 * Returns: macRadioErr_t
 */
int32_t macRadioSetPeripheralMode(macRadio_t *inst);

/**
 * Send a packet on an active connection
 * Input: Pointer to mac radio instance
 * Input: Pointer to a mac packet
 * Returns: macRadioErr_t
 */
int32_t macRadioSendOnConnection(macRadio_t *inst, macRadioPacket_t *packet);

#endif /* MAC_RADIO_H */