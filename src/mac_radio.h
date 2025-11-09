/**
 * @file:       mac_radio.h
 * @author:     Lucas Wennerholm <lucas.wennerholm@gmail.com>
 * @brief:      Header file for the radio mac layer
 * @details:    This layer manages connections, device roles, acknowlaged packets, stream packets
 *
 * @license: Apache 2.0
 *
 * Copyright 2025 Lucas Wennerholm
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MAC_RADIO_H
#define MAC_RADIO_H

#ifdef __cplusplus
extern "C" {
#endif
#include "pico/stdlib.h"
#include "phy_radio.h"
#include "c_buffer.h"
#include "static_pool.h"
#include "static_map.h"

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, member)	(type *)((char *)(ptr) - offsetof(type,member))
#endif

// Packet size and overhead
#define MAC_RADIO_PKT_TYPE_SIZE   (1)
#define MAC_RADIO_MSG_ID_SIZE     (1)
#define MAC_RADIO_OVERHEAD_SIZE   (MAC_RADIO_PKT_TYPE_SIZE + MAC_RADIO_MSG_ID_SIZE)
#define MAC_RADIO_MAX_PACKET_SIZE (PHY_RADIO_MAX_PACKET_SIZE - MAC_RADIO_OVERHEAD_SIZE)

// Internal packets
#define MAC_RADIO_INTERNAL_MSG_SIZE        (MAC_RADIO_OVERHEAD_SIZE)
#define MAC_RADIO_INTERNAL_MSG_BUFFER_SIZE (MAC_RADIO_INTERNAL_MSG_SIZE + PHY_RADIO_TOTAL_OVERHEAD_SIZE + C_BUFFER_ARRAY_OVERHEAD)

// Packet management
#ifndef MAC_RADIO_POOL_SIZE
#define MAC_RADIO_POOL_SIZE (5)
#endif /* MAC_RADIO_POOL_SIZE */

#ifndef MAC_RADIO_MAP_SIZE
#define MAC_RADIO_MAP_SIZE (5)
#endif /* MAC_RADIO_MAP_SIZE */

#ifndef MAC_RADIO_MAX_NUM_CONNECTIONS
#define MAC_RADIO_MAX_NUM_CONNECTIONS (2)
#endif /* MAC_RADIO_MAX_NUM_CONNECTIONS */

#ifndef MAC_RADIO_SYNC_INTERVAL
#define MAC_RADIO_SYNC_INTERVAL (2)
#endif /* MAC_RADIO_SYNC_INTERVAL */

#ifndef MAC_RADIO_CENTRAL_SLOT
#define MAC_RADIO_CENTRAL_SLOT (1)
#endif /* MAC_RADIO_CENTRAL_SLOT */

#ifdef MAC_RADIO_MODE_DBG_LED
#ifndef MAC_RADIO_MODE_DBG_LED_PIN
#define MAC_RADIO_MODE_DBG_LED_PIN (13)
#endif /* MAC_RADIO_MODE_DBG_LED_PIN */
#endif /* MAC_RADIO_MODE_DBG_LED */

// Max Number of missed keep alive from peripheral before a disconnect is triggered
#define MAC_RADIO_SYNC_TIMEOUT (PHY_RADIO_SYNC_TIMEOUT) // Use the same as Peripheral timeout

typedef enum {
    MAC_RADIO_INTERRUPT_IN_QUEUE = 1,
    MAC_RADIO_SUCCESS            = 0,
    MAC_RADIO_NULL_ERROR    = -30001,
    MAC_RADIO_INVALID_ERROR = -30002,
    MAC_RADIO_POOL_ERROR    = -30003,
    MAC_RADIO_MAP_ERROR     = -30004,
    MAC_RADIO_BUFFER_ERROR  = -30009,
    MAC_RADIO_NO_CONN_ERROR = -30010,
    MAC_RADIO_PKT_TIMEOUT   = -30011,
    MAC_RADIO_UNKONWN_ACK   = -30012,
    MAC_RADIO_NEW_CONN_ERR  = -30013,
    MAC_RADIO_NO_SLOTS      = -30014,
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
    MAC_RADIO_RELIABLE_PKT,  // This packet expects an acknowlagement, times out if no ack is sent
    MAC_RADIO_STREAM_PKT,    // This packet is not acknowlaged
    MAC_RADIO_BROADCAST_PKT, // This packet is heard by any listener
    MAC_RADIO_CLOSE_PKT,
    MAC_RADIO_HANDOVER_PKT,
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
    uint16_t   user_id; // This field can be used by the higher layer to identify the packet
    uint16_t   reserved_space; // Unused field reserved for future use
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
    uint8_t num_data_slots;
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
    phyRadioPacket_t *phy_pkt;
    uint32_t          ttl;
    bool              sent;
    bool              internal;
    staticMapItem_t   node;
} macRadioPktTrackItem_t;

typedef struct {
    uint32_t        last_heard; // Last time we heard from a device
    uint32_t        conn_state;
    uint8_t         target_tx_slot;
    uint8_t         target_addr;
    staticMapItem_t node;
} macRadioConnItem_t;

typedef struct {
    // Mode and configuration
    macRadioConfig_t current_config;
    macRadioMode_t   mode;
    uint8_t          auto_counter;
    uint8_t          switch_counter;
    uint8_t          switch_addr;

    // Frame configuration
    phyRadioFrameConfig_t frame_config;

    // Connection management
    uint8_t            central_addr;
    uint8_t            my_tx_slot; // Each device only has one TX slot
    staticMap_t        connections;
    staticMapItem_t*   _array[MAC_RADIO_MAX_NUM_CONNECTIONS];
    macRadioConnItem_t _con_items[MAC_RADIO_MAX_NUM_CONNECTIONS];

    // Slot access configuration
    uint8_t            slot_config_data[PHY_RADIO_SYNC_GEN_DATA_SIZE];

    // Internal Packet management
    macRadioBufferPoolItem_t _buffer_pkt_pool[MAC_RADIO_POOL_SIZE];
    staticPoolList_t         _buffer_pool_array[MAC_RADIO_POOL_SIZE];
    staticPool_t             buffer_packet_pool;
    staticMap_t              track_map;
    staticMapItem_t*         _map_array[MAC_RADIO_MAP_SIZE];
    macRadioPktTrackItem_t   _track_map_array[MAC_RADIO_MAP_SIZE];

    // External Packet management
    uint8_t               msg_id;
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
 * Input: Pointer to config
 * Input: Pointer to interface
 * Returns: macRadioErr_t
 */
int32_t macRadioInit(macRadio_t *inst, macRadioConfig_t config, macRadioInterface_t *interface);

/**
 * Deinit this module.
 * Input: Pointer to mac radio instance
 * Returns: macRadioErr_t
 */
int32_t macRadioDeInit(macRadio_t *inst);

/**
 * Process the mac radio
 * Input: macRadio instance
 * Returns: macRadioErr_t
 */
int32_t macRadioProcess(macRadio_t *inst);

/**
 * Check if the mac radio needs to be processed
 * Input: macRadio instance
 * Returns: macRadioErr_t
 */
int32_t macRadioEventInQueue(macRadio_t *inst);

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

/**
 * Handover the central role to another device, only valid if this device currently is central
 * If this succeeds this device will become peripheral
 * Input: Pointer to mac radio instance
 * Input: The address to the next device intended as central
 * Returns: macRadioErr_t
 */
int32_t macRadioSwitchCentral(macRadio_t *inst, uint8_t next_central_addr);

#ifdef __cplusplus
}
#endif
#endif /* MAC_RADIO_H */