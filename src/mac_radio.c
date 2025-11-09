/**
 * @file:       mac_radio.c
 * @author:     Lucas Wennerholm <lucas.wennerholm@gmail.com>
 * @brief:      Implementation of radio mac layer
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

#include "mac_radio.h"
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

// Weakly defined logging function - can be overridden by user
__attribute__((weak)) void radio_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

#define DEFAULT_TTL 1

#ifndef MAC_RADIO_LOG_ENABLE
#define MAC_RADIO_LOG_ENABLE (1)
#endif /* MAC_RADIO_LOG_ENABLE */

#if MAC_RADIO_LOG_ENABLE == 1
#define LOG(f_, ...) radio_log((f_), ##__VA_ARGS__)
#else
#define LOG(f_, ...)
#endif /* MAC_RADIO_LOG_ENABLE */

#ifdef MAC_RADIO_LOG_DEBUG_ENABLE
#define LOG_DEBUG(f_, ...) radio_log((f_), ##__VA_ARGS__)
#else
#define LOG_DEBUG(f_, ...)
#endif /* MAC_RADIO_LOG_DEBUG_ENABLE */

#ifdef MAC_RADIO_LOG_V_DEBUG_ENABLE
#define LOG_V_DEBUG(f_, ...) radio_log((f_), ##__VA_ARGS__)
#else
#define LOG_V_DEBUG(f_, ...)
#endif /* MAC_RADIO_LOG_V_DEBUG_ENABLE */

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#define MAC_RADIO_DEFAULT_NUM_BEACONS     (8)
#define MAC_RADIO_MIN_NUM_BEACONS         (2)
#define MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS (10*5*8)
#define MAC_RADIO_MIN_SCAN_TIMEOUT_MS     (5*5*8)

static int32_t clearSlotFromConfig(macRadio_t *inst, uint8_t slot);
static int32_t InternalSendOnConnection(macRadio_t *inst, macRadioPacketType_t packet_type, uint8_t use_msg_id, uint8_t target_addr);

static int32_t releasePacketByPhy(macRadio_t *inst, phyRadioPacket_t *packet) {
    // Get the Packetitem associated with this packet
    macRadioPktPoolItem_t * packet_item = CONTAINER_OF(packet, macRadioPktPoolItem_t, packet);
    // Return the node of the packet item to the pool
    return staticPoolRelease(&inst->packet_pool, &packet_item->node);
}

static int32_t releasePacketByItem(macRadio_t *inst, macRadioPktPoolItem_t *item) {
    return staticPoolRelease(&inst->packet_pool, &item->node);
}

static macRadioPktPoolItem_t * getPacketItemFromPhyPkt(macRadio_t *inst, phyRadioPacket_t *packet) {
    // Get the Packetitem associated with this packet
    macRadioPktPoolItem_t * packet_item = CONTAINER_OF(packet, macRadioPktPoolItem_t, packet);
    return packet_item;
}

static macRadioPktPoolItem_t * aquirePacket(macRadio_t *inst) {
    staticPoolItem_t* pool_item = staticPoolAcquire(&inst->packet_pool);
    if (pool_item == NULL) {
        return NULL;
    }

    macRadioPktPoolItem_t * packet_item = CONTAINER_OF(pool_item, macRadioPktPoolItem_t, node);
    return packet_item;
}

static int32_t releaseBufferByMac(macRadio_t *inst, macRadioPacket_t* mac_pkt) {
    // Get the Bufferitem associated with this buffer
    macRadioBufferPoolItem_t * buffer_item = CONTAINER_OF(mac_pkt, macRadioBufferPoolItem_t, mac_pkt);
    // Return the node of the packet item to the pool
    return staticPoolRelease(&inst->buffer_packet_pool, &buffer_item->node);
}

static int32_t releaseBufferByBuf(macRadio_t *inst, cBuffer_t *buffer) {
    // Get the Bufferitem associated with this buffer
    macRadioBufferPoolItem_t * buffer_item = CONTAINER_OF(buffer, macRadioBufferPoolItem_t, msg_buf);
    // Return the node of the packet item to the pool
    return staticPoolRelease(&inst->buffer_packet_pool, &buffer_item->node);
}

static macRadioBufferPoolItem_t * aquireBuffer(macRadio_t *inst) {
    staticPoolItem_t* pool_item = staticPoolAcquire(&inst->buffer_packet_pool);
    if (pool_item == NULL) {
        return NULL;
    }

    macRadioBufferPoolItem_t * buffer_item = CONTAINER_OF(pool_item, macRadioBufferPoolItem_t, node);
    return buffer_item;
}

static macRadioPktTrackItem_t * trackMacPacket(staticMap_t *map, macRadioPacket_t *pkt, uint32_t msg_id) {
    staticMapItem_t * map_item = staticMapInsertAndGet(map, msg_id);
    if (map_item == NULL) {
        return NULL;
    }

    macRadioPktTrackItem_t * track_item = CONTAINER_OF(map_item, macRadioPktTrackItem_t, node);

    track_item->mac_pkt  = pkt;
    track_item->sent     = false;
    track_item->ttl      = DEFAULT_TTL;
    track_item->internal = false;

    return track_item;
}

static macRadioPktTrackItem_t * findTrackedMacPkt(staticMap_t *map, uint32_t msg_id) {
    staticMapItem_t * map_item = staticMapFind(map, msg_id);
    if (map_item == NULL) {
        return NULL;
    }

    macRadioPktTrackItem_t * track_item = CONTAINER_OF(map_item, macRadioPktTrackItem_t, node);

    return track_item;
}

static uint32_t unTrackMacPktByItem(staticMap_t *map, macRadioPktTrackItem_t *item) {
    int32_t result = staticMapRemove(map, &item->node);
    return result;
}

static uint32_t unTrackPktByKey(staticMap_t *map, uint32_t key) {
    int32_t result = staticMapRemoveByKey(map, key);
    return result;
}

static macRadioConnItem_t* newConnection(staticMap_t *map, uint32_t conn_id) {
    staticMapItem_t * map_item = staticMapInsertAndGet(map, conn_id);
    if (map_item == NULL) {
        return NULL;
    }

    macRadioConnItem_t* conn_item = CONTAINER_OF(map_item, macRadioConnItem_t, node);

    conn_item->conn_state     = MAC_RADIO_DISCONNECTED;
    conn_item->last_heard     = 0;
    conn_item->target_tx_slot = 0;
    conn_item->target_addr    = conn_id;

    return conn_item;
}

static macRadioConnItem_t* getConnection(staticMap_t *map, uint32_t conn_id) {
    staticMapItem_t * map_item = staticMapFind(map, conn_id);
    if (map_item == NULL) {
        return NULL;
    }

    macRadioConnItem_t * conn_item = CONTAINER_OF(map_item, macRadioConnItem_t, node);

    return conn_item;
}

static macRadioConnItem_t* getOrCreateNewConnection(staticMap_t *map, uint32_t conn_id) {
    staticMapItem_t * map_item = staticMapFind(map, conn_id);
    if (map_item != NULL) {
        macRadioConnItem_t * conn_item = CONTAINER_OF(map_item, macRadioConnItem_t, node);
        return conn_item;
    }

    return newConnection(map, conn_id);
}

static uint32_t deleteConnection(staticMap_t *map, uint32_t conn_id) {
    int32_t result = staticMapRemoveByKey(map, conn_id);
    return result;
}

static int32_t clearSlotFromConfig(macRadio_t *inst, uint8_t slot) {
    // Slot must be a valid number
    if (slot < 1) {
        return MAC_RADIO_INVALID_ERROR;
    }

    inst->slot_config_data[0] &= ~(1 << (slot - 1));

    // Update the PHY layer with the new slot configuration
    int32_t res = phyRadioSetCustomData(&inst->phy_instance, inst->slot_config_data, PHY_RADIO_SYNC_GEN_DATA_SIZE);
    if (res != PHY_RADIO_SUCCESS) {
        return res;
    }

    return MAC_RADIO_SUCCESS;
}

static int32_t disconnectAndNotify(macRadio_t *inst, macRadioConnItem_t *connection) {
    // Check if we are allready disconnected
    if (connection->conn_state == MAC_RADIO_DISCONNECTED) {
        return MAC_RADIO_SUCCESS;
    }

    connection->conn_state = MAC_RADIO_DISCONNECTED;

    // Clear the slot used by this connection
    int32_t res = clearSlotFromConfig(inst, connection->target_tx_slot);
    if (res != PHY_RADIO_SUCCESS) {
        return res;
    }

    // Trigger connection Callback
    macRadioConn_t new_connection = {
        .conn_id = connection->target_addr,
        .conn_state = MAC_RADIO_DISCONNECTED,
    };

    // Re-Init the auto mode counter to a random value
    inst->auto_counter = (uint8_t)(rand() % MAC_RADIO_DEFAULT_NUM_BEACONS) + MAC_RADIO_MIN_NUM_BEACONS;

    return inst->interface->conn_cb(inst->interface, new_connection);
}

static int32_t connItemCb(staticMap_t *map, staticMapItem_t *map_item) {
    macRadioConnItem_t* conn_item = CONTAINER_OF(map_item, macRadioConnItem_t, node);
    macRadio_t * inst = CONTAINER_OF(map, macRadio_t, connections);

    conn_item->last_heard++;

    // Check if the connection has timed out
    if (conn_item->last_heard > MAC_RADIO_SYNC_TIMEOUT && conn_item->conn_state == MAC_RADIO_CONNECTED) {
        // Connection lost
        int32_t cb_retval = disconnectAndNotify(inst, conn_item);
        if (cb_retval != MAC_RADIO_CB_SUCCESS) {
            return cb_retval;
        }

        // Delete this connection
        return STATIC_MAP_CB_ERASE;
    }

    return STATIC_MAP_CB_NEXT;
}

static int32_t nextDeviceCb(staticMap_t *map, staticMapItem_t *map_item) {
    macRadioConnItem_t* conn_item = CONTAINER_OF(map_item, macRadioConnItem_t, node);
    macRadio_t * inst = CONTAINER_OF(map, macRadio_t, connections);

    if (conn_item->conn_state == MAC_RADIO_CONNECTED) {
        inst->switch_addr = conn_item->target_addr;

        if (rand() % 2 == 0) {
            return STATIC_MAP_CB_STOP;
        }
    }
    return STATIC_MAP_CB_NEXT;
}

static int32_t manageCentralSyncSent(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // Loop through all active connections and check if any has timed out
    int32_t res = staticMapForEach(&inst->connections, connItemCb);
    if (res != STATIC_MAP_SUCCESS) {
        return res;
    }

    int32_t num_conns = staticMapGetNumItems(&inst->connections);

    // If we have no active connections, and are in auto mode
    if (num_conns == 0 && inst->mode == MAC_RADIO_AUTO_MODE) {
        // TODO this might not be the fastest to turn around on last connection

        // Check if it is time to switch mode
        if (inst->auto_counter == 0) {

#ifdef MAC_RADIO_MODE_DBG_LED
            gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

            // Switch to scan mode
            int32_t res = phyRadioSetScanMode(&inst->phy_instance, (rand() % MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS) + MAC_RADIO_MIN_SCAN_TIMEOUT_MS);

            if (res != PHY_RADIO_SUCCESS) {
                return res;
            }
        } else {
            // Decrement the scan counter
            inst->auto_counter--;
        }

    }
#ifdef AUTO_SWITCH
     else if (inst->switch_counter > 0) {
        inst->switch_counter--;
        if (inst->switch_counter == 0) {
            // Loop through all active connections and check if any has timed out
            int32_t res = staticMapForEach(&inst->connections, nextDeviceCb);
            if (res != STATIC_MAP_SUCCESS) {
                return res;
            }

            res = macRadioSwitchCentral(inst, inst->switch_addr);
            if (res != MAC_RADIO_SUCCESS) {
                return res;
            }
        }
    }
#endif

    // TODO what happens if this callback comes when we are waiting for a reliable packet?
    return PHY_RADIO_CB_SUCCESS;
}

static int32_t configureMySlots(macRadio_t *inst) {
    int32_t res = MAC_RADIO_SUCCESS;

    for (int i = 1; i < PHY_RADIO_NUM_SLOTS; i++) {
        // Receive on slot 1 indefinetly
        if ((res = phyRadioReceiveOnSlot(&inst->phy_instance, i)) != PHY_RADIO_SUCCESS) {
            LOG("RADIO SET MODE FAILED! %i\n", res);
            return res;
        }
    }

    return res;
}

static int32_t manageSlotDataFromCentral(macRadio_t *inst, uint8_t slot_data, macRadioConnItem_t* central_con) {

    // Check what slot the central device is using (bits 7-5)
    uint8_t central_slot = (slot_data >> 5) & 0x07;

    // Store what tx slot is used by the central
    central_con->target_tx_slot = central_slot;

    // Store the central's slot in our local slot_config_data (bits 7-5)
    inst->slot_config_data[0] = (central_slot & 0x07) << 5;

    // Check available slots (bits 4-0)
    // Bit = 1 means occupied, bit = 0 means free
    uint8_t free_slots_mask = slot_data & 0x1F;

    // Mark the central's slot as occupied in our local mask
    // Slot numbers are 1-indexed, bit positions are 0-indexed
    inst->slot_config_data[0] |= (1 << (central_slot - 1));

    // Find first available slot (where bit is 0)
    // __builtin_ctz counts trailing zeros, so invert the mask first
    int available_bit = __builtin_ctz(~free_slots_mask);

    // Check if the available slot is within valid range
    if (available_bit < inst->current_config.num_data_slots) {
        // Convert bit position to slot number (slots are 1-indexed)
        inst->my_tx_slot = available_bit + 1;

        // Mark this slot as occupied in our local mask
        inst->slot_config_data[0] |= (1 << available_bit);
    } else {
        // No available slots
        return MAC_RADIO_NO_SLOTS;
    }

    return MAC_RADIO_SUCCESS;
}

static int32_t setCentralSlot(macRadio_t *inst, uint8_t slot) {
    if (slot < 1) {
        return MAC_RADIO_INVALID_ERROR;
    }

    // Set what slot is used by the central (bits 7-5)
    inst->slot_config_data[0] = (slot & 0x07) << 5;

    // Mark the central's slot as occupied in the free_slots_mask (bits 4-0)
    // Bit = 1 means occupied, bit = 0 means free
    // Slot numbers are 1-indexed, bit positions are 0-indexed
    inst->slot_config_data[0] |= (1 << (slot - 1));

    inst->my_tx_slot = slot;

    return MAC_RADIO_SUCCESS;
}

static int32_t managePeripheralFirstSync(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // Try to create a new connection instance
    macRadioConnItem_t* new_conn = getOrCreateNewConnection(&inst->connections, sync_state->central_address);

    // We are out of available connections
    if (new_conn == NULL) {
        LOG("Out of connections!\n");
        return MAC_RADIO_NEW_CONN_ERR;
    }
    LOG("First SYNC\n");

    int32_t res = manageSlotDataFromCentral(inst, sync_state->custom_data[0], new_conn);
    if (res != MAC_RADIO_SUCCESS) {
        LOG("NO SLOT %i \n", sync_state->custom_data[0]);
        // There are no slots available
        return MAC_RADIO_SUCCESS;
    }

    LOG("SLOT %i \n", inst->my_tx_slot);

    // New sync detected
    new_conn->conn_state = MAC_RADIO_CONNECTING;

    // Store the central address and my assigned TX slot
    new_conn->target_addr = sync_state->central_address;

    // Configure my slots
    res = configureMySlots(inst);
    if (res != MAC_RADIO_SUCCESS) {
        return res;
    }

    // Inform the phy layer to enter peripheral mode
    return PHY_RADIO_CB_SET_PERIPHERAL;
}

static int32_t managePeripheralReSync(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // Try to find the connection instance
    macRadioConnItem_t* conn = getConnection(&inst->connections, sync_state->central_address);
    // Check if this connection exists
    if (conn == NULL) {
        return MAC_RADIO_NO_CONN_ERROR;
    }

    // Check if we are connecting, if so send a sync_ack
    if (conn->conn_state == MAC_RADIO_CONNECTING) {
        // Trigger a connect request
        return InternalSendOnConnection(inst, MAC_RADIO_SYNC_ACK_PKT, 0, conn->target_addr);
    }

    // If we are connected send a keep alive, to notify the central that we exist
    // TODO we should only do this if we are not sending regular packets ..
    if (conn->conn_state == MAC_RADIO_CONNECTED) {
        // Trigger an alive packet
        int32_t res = MAC_RADIO_SUCCESS;
        if ((res = InternalSendOnConnection(inst, MAC_RADIO_KEEP_ALIVE_PKT, 0, conn->target_addr)) != MAC_RADIO_SUCCESS) {
            return res;
        }
    }

    // Inform the phy to stay in current mode
    return PHY_RADIO_CB_SUCCESS;
}

static int32_t connItemDisconnectCb(staticMap_t *map, staticMapItem_t *map_item) {
    macRadioConnItem_t* conn_item = CONTAINER_OF(map_item, macRadioConnItem_t, node);
    macRadio_t * inst = CONTAINER_OF(map, macRadio_t, connections);

    // Notify disconnected if a complete connection
    if (conn_item->conn_state == MAC_RADIO_CONNECTED) {
        int32_t cb_retval = disconnectAndNotify(inst, conn_item);
        if (cb_retval != MAC_RADIO_CB_SUCCESS) {
            return cb_retval;
        }
    }
 
    // Delete this connection
    return STATIC_MAP_CB_ERASE;
}

static int32_t managePeripheralSyncLost(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // Sync was lost, set the state to disconnected for all connections
    int32_t res = staticMapForEach(&inst->connections, connItemDisconnectCb);
    if (res != STATIC_MAP_SUCCESS) {
        return res;
    }

    // Manage auto mode
    if (inst->mode == MAC_RADIO_AUTO_MODE) {

#ifdef MAC_RADIO_MODE_DBG_LED
        gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

        // If we are in auto mode return to scan on disconnect
        int32_t res = phyRadioSetScanMode(&inst->phy_instance, (rand() % MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS) + MAC_RADIO_MIN_SCAN_TIMEOUT_MS);
        if (res != PHY_RADIO_SUCCESS) {
            return res;
        }
        return PHY_RADIO_CB_SUCCESS;
    }

#ifdef MAC_RADIO_MODE_DBG_LED
    gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

    // TODO what happens if this callback comes when we are waiting for a reliable packet?
    // Inform the phy layer to return to scan mode
    return PHY_RADIO_CB_SET_SCAN;
}

static int32_t manageInternalPackageTimeout(macRadio_t *inst, macRadioPacket_t *pkt) {
    switch (pkt->pkt_type) {
        case MAC_RADIO_HANDOVER_PKT:
            LOG("Handover Timeout\n");
#ifdef AUTO_SWITCH
            // Reset the handover counter
            inst->switch_counter = 4;
            // TODO This risks creating multiple centrals
#endif
            break;
        case MAC_RADIO_SYNC_ACK_PKT:
            // Currently we risk getting stuck in CONNECTING state ..
            // TODO manage this
            break;
        case MAC_RADIO_RELIABLE_PKT:
            break;
        default:
            break;
    }

    return MAC_RADIO_SUCCESS;
}

static int32_t mapItemCb(staticMap_t *map, staticMapItem_t *map_item) {
    macRadioPktTrackItem_t * track_item = CONTAINER_OF(map_item, macRadioPktTrackItem_t, node);
    macRadio_t * inst = CONTAINER_OF(map, macRadio_t, track_map);

    if (track_item->ttl == 0) {
        // Check if it is an external or internal packet that has timed out
        if (track_item->internal) {
            int32_t res = MAC_RADIO_SUCCESS;
            // Manage pkt timeout
            if ((res = manageInternalPackageTimeout(inst, track_item->mac_pkt)) != MAC_RADIO_SUCCESS) {
                return res;
            }

            // Release buffers used by internal packets
            res = releaseBufferByMac(inst, track_item->mac_pkt);
            if (res != STATIC_POOL_SUCCESS) {
                // Fatal, something is very bad
                return res;
            }

            // Nothing more to do, stop tracking this packet
            return STATIC_MAP_CB_ERASE;
        }

        // Manage external packet timeout
        if (track_item->mac_pkt->pkt_type == MAC_RADIO_RELIABLE_PKT) {
            // Notify that a packet has been lost
            int32_t cb_retval = inst->interface->resp_cb(inst->interface, track_item->mac_pkt, NULL, MAC_RADIO_PKT_TIMEOUT);
            if (cb_retval != MAC_RADIO_CB_SUCCESS) {
                return cb_retval;
            }
        }

        return STATIC_MAP_CB_ERASE;
    }

    // If the item is not yet sent we do not have to do anything more
    if (!track_item->sent) {
        return STATIC_MAP_CB_NEXT;
    }

    track_item->ttl--;

    return STATIC_MAP_CB_NEXT;
}

static int32_t managePhyFrameStart(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // We use this notification to manage packet timeouts, loop through all active packets
    int32_t res = staticMapForEach(&inst->track_map, mapItemCb);
    if (res != STATIC_MAP_SUCCESS) {
        return res;
    }

    return PHY_RADIO_CB_SUCCESS;
}

static int32_t manageCentralConflictingSync(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // TODO We could decide more in detail how we should manage conflicting syncs, but for now
    // we allways disconnect and go to scan mode.
    switch(inst->mode) {
        case MAC_RADIO_CENTRAL:
        case MAC_RADIO_PERIPHERAL:
        case MAC_RADIO_AUTO_MODE:
            break;
        default:
            break;
    }

    // Make sure to trigger a disconnect on all connections if we where connected
    int32_t res = staticMapForEach(&inst->connections, connItemDisconnectCb);
    if (res != STATIC_MAP_SUCCESS) {
        return res;
    }

    // Reset the slot config
    for (int32_t i = 0; i < PHY_RADIO_SYNC_GEN_DATA_SIZE; i++) {
        inst->slot_config_data[i] = 0x00;
    }

#ifdef MAC_RADIO_MODE_DBG_LED
    gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

    // Inform phy to enter scan mode
    return PHY_RADIO_CB_SET_SCAN;
}

static int32_t manageScanTimeout(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // Check what mode we are in
    if (inst->mode != MAC_RADIO_AUTO_MODE) {
        // Nothing more to do, just return
        return PHY_RADIO_CB_SUCCESS;
    }

    // Re-Init the auto mode counter to a random value
    inst->auto_counter = (uint8_t)(rand() % MAC_RADIO_DEFAULT_NUM_BEACONS) + MAC_RADIO_MIN_NUM_BEACONS;

#ifdef MAC_RADIO_MODE_DBG_LED
    gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, true);
#endif /* MAC_RADIO_MODE_DBG_LED */

    // Switch to central mode
    int32_t res = phyRadioSetCentralMode(&inst->phy_instance);
    if (res != PHY_RADIO_SUCCESS) {
        return res;
    }

    // Configure the central to use slot
    if ((res = setCentralSlot(inst, MAC_RADIO_CENTRAL_SLOT)) != MAC_RADIO_SUCCESS) {
        return res;
    }

    // Set all slots as available in the sync message
    res = phyRadioSetCustomData(&inst->phy_instance, inst->slot_config_data, PHY_RADIO_SYNC_GEN_DATA_SIZE);

    res = configureMySlots(inst);
    if (res != MAC_RADIO_SUCCESS) {
        return res;
    }

    return PHY_RADIO_CB_SUCCESS;
}

static int32_t phySyncStateCb(phyRadioInterface_t *interface, uint32_t sync_id, const phyRadioSyncState_t *sync_state) {
    macRadio_t * inst = CONTAINER_OF(interface, macRadio_t, phy_interface);

    switch (sync_id) {
        case PHY_RADIO_SYNC_SENT:
            return manageCentralSyncSent(inst, sync_state);
        case PHY_RADIO_FIRST_SYNC:
            return managePeripheralFirstSync(inst, sync_state);
        case PHY_RADIO_RE_SYNC:
            return managePeripheralReSync(inst, sync_state);
        case PHY_RADIO_CONFLICT_SYNC:
            return manageCentralConflictingSync(inst, sync_state);
        case PHY_RADIO_SYNC_LOST:
            return managePeripheralSyncLost(inst, sync_state);
        case PHY_RADIO_FRAME_START:
            return managePhyFrameStart(inst, sync_state);
        case PHY_RADIO_RX_SLOT_START:
            break;
        case PHY_RADIO_TX_SLOT_START:
            break;
        case PHY_RADIO_SCAN_TIMEOUT:
            return manageScanTimeout(inst, sync_state);
        default:
            // We should never end up here!
            return PHY_RADIO_CB_ERROR_INVALID;
    }

    return PHY_RADIO_CB_SUCCESS;
}

static int32_t phyPacketSent(phyRadioInterface_t *interface, phyRadioPacket_t *packet, phyRadioErr_t result) {
    macRadio_t * inst = CONTAINER_OF(interface, macRadio_t, phy_interface);

    if (packet == NULL) {
        // This would be very bad
        LOG("PHY packet is NULL!\n");
        return MAC_RADIO_NULL_ERROR;
    }

    // Get the pointer to the original packet
    macRadioPktPoolItem_t *packet_item = getPacketItemFromPhyPkt(inst, packet);

    if (packet_item == NULL) {
        // This would be very bad
        return MAC_RADIO_POOL_ERROR;
    }

    macRadioPacket_t *mac_pkt = packet_item->mac_pkt;
    bool mac_interal          = packet_item->internal; // Is this an mac internal packet?
    uint8_t msg_id            = packet_item->msg_id;

    // Return the phy packet to the pool
    int32_t res = releasePacketByItem(inst, packet_item);

    if (res != STATIC_POOL_SUCCESS) {
        // If this fails something is very broken
        LOG("Failed ret pkt to POOL %i %i\n", res, result);
        if (!mac_interal) {
            return inst->interface->sent_cb(inst->interface, mac_pkt, MAC_RADIO_POOL_ERROR);
        } else {
            return MAC_RADIO_SUCCESS;
        }
    }

    macRadioPktTrackItem_t *track_item = NULL;
    switch(mac_pkt->pkt_type) {
        case MAC_RADIO_SYNC_ACK_PKT:
        case MAC_RADIO_HANDOVER_PKT:
        case MAC_RADIO_RELIABLE_PKT: {
            // Manage acknowlaged packets
            if (result != PHY_RADIO_SUCCESS) {
                // If a send fails we should remove it from the map
                // i.e it was never sent and there will never be an acknowlagement
                if ((res = unTrackPktByKey(&inst->track_map, msg_id)) != STATIC_MAP_SUCCESS) {
                    // This is a fatal error, something is very bad
                    return res;
                }

                if (mac_interal) {
                    // Release the buffer used for this internal message
                    if ((res = releaseBufferByBuf(inst, packet->pkt_buffer)) != STATIC_POOL_SUCCESS) {
                        // This is a fatal error, something is very bad
                        LOG("Failed ret buf to POOL %i\n", res);
                        return res;
                    }
                }
            } else {
                // if the send result was successfull, set this packet as sent
                track_item = findTrackedMacPkt(&inst->track_map, msg_id);
                if (track_item == NULL) {
                    // This is a fatal error, something is very bad
                    LOG("Sent map error %i %u %i\n", msg_id, inst, result);
                    return MAC_RADIO_MAP_ERROR;
                }
                track_item->sent = true;
            }
        } break;
        case MAC_RADIO_SYNC_PKT:
        case MAC_RADIO_ACK_PKT:
        case MAC_RADIO_KEEP_ALIVE_PKT:
        case MAC_RADIO_CLOSE_PKT:
        case MAC_RADIO_STREAM_PKT:
        case MAC_RADIO_BROADCAST_PKT:
            // Check if it is an internal mac layer message.
            if (mac_interal) {
                // Release the buffer used for this internal message
                if ((res = releaseBufferByBuf(inst, packet->pkt_buffer)) != STATIC_POOL_SUCCESS) {
                    // Fatal, this would be very bad
                    LOG("Failed to ret buf to POOL %i\n", res);
                    return res;
                }
            }
            break;
        default:
            return MAC_RADIO_INVALID_ERROR;
    }

    // If it is an internal package there is nothing more to do, return
    if (mac_interal) {
        return PHY_RADIO_CB_SUCCESS;
    }

    // Notify that an external packet has been sent
    int32_t cb_retval = inst->interface->sent_cb(inst->interface, mac_pkt, result);

    if (cb_retval != MAC_RADIO_CB_SUCCESS) {
        return cb_retval;
    }

    return PHY_RADIO_CB_SUCCESS;
}

static int32_t manageAckPkt(macRadio_t * inst, uint32_t src_addr, macRadioPktTrackItem_t * track_item)  {
    if (track_item == NULL) {
        // This is an acknowlagement sent on an unkonwn msg_id
        LOG("BAD/OLD ACK\n");
        // Most likely this is a message that has allready timed out
        return MAC_RADIO_CB_SUCCESS;
    }

    int32_t cb_retval = MAC_RADIO_CB_SUCCESS;

    // Get the original packet sent
    macRadioPacket_t *mac_pkt = track_item->mac_pkt;

    // Manage the tracked packet type
    switch (mac_pkt->pkt_type) {
        case MAC_RADIO_SYNC_ACK_PKT: {
            uint32_t conn_id = mac_pkt->conn_id;

            int32_t res = MAC_RADIO_SUCCESS;
            // Release the internal buffer used for this message, MAC_RADIO_SYNC_ACK_PKT, is allways internal
            if ((res = releaseBufferByMac(inst, mac_pkt)) != STATIC_POOL_SUCCESS) {
                return res;
            }

            // Remove the packet from the map
            if ((res = unTrackMacPktByItem(&inst->track_map, track_item)) != STATIC_MAP_SUCCESS) {
                return res;
            }

            // Find the connection
            macRadioConnItem_t* conn = getConnection(&inst->connections, src_addr);

            if (conn == NULL) {
                // This was not a packet to me
                // TODO what to do??
                break;
            }

            // The SynAck was Acked, go to connected mode
            if (conn->conn_state == MAC_RADIO_CONNECTING) {
                conn->conn_state = MAC_RADIO_CONNECTED;

                // Trigger connected Callback
                macRadioConn_t new_connection = {
                    .conn_id = src_addr,
                    .conn_state = MAC_RADIO_CONNECTED,
                };

                // Manage connections
                LOG_DEBUG("Connected as PERIPHERAL\n");
                cb_retval = inst->interface->conn_cb(inst->interface, new_connection);
            }
        } break; 

        case MAC_RADIO_HANDOVER_PKT: {
            uint32_t conn_id = mac_pkt->conn_id;

            int32_t res = MAC_RADIO_SUCCESS;
            // Release the internal buffer used for this message, MAC_RADIO_SYNC_ACK_PKT, is allways internal
            if ((res = releaseBufferByMac(inst, mac_pkt)) != STATIC_POOL_SUCCESS) {
                return res;
            }

            // Remove the packet from the map
            if ((res = unTrackMacPktByItem(&inst->track_map, track_item)) != STATIC_MAP_SUCCESS) {
                return res;
            }

            // Find the connection
            macRadioConnItem_t* conn = getConnection(&inst->connections, src_addr);

            if (conn == NULL) {
                // This was not a packet to me
                // TODO what to do??
                break;
            }

#ifdef MAC_RADIO_MODE_DBG_LED
            gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

            res = phyRadioTransitionCentralToPeripheral(&inst->phy_instance, inst->central_addr);
            if (res != PHY_RADIO_SUCCESS) {
                return res;
            }
        } break; 
        case MAC_RADIO_RELIABLE_PKT: {
            if (track_item->internal) {
                int32_t res = MAC_RADIO_SUCCESS;
                // Release the internal buffer used for this message
                if ((res = releaseBufferByMac(inst, mac_pkt)) != STATIC_POOL_SUCCESS) {
                    // Fatal, something is very bad
                    return res;
                }

                // Remove the packet from the map
                if ((res = unTrackMacPktByItem(&inst->track_map, track_item)) != STATIC_MAP_SUCCESS) {
                    return res;
                }

                // Stop before calling the resp_cb
                break;
            }

            // Packet was acknowlaged, inform higher layer
            cb_retval = inst->interface->resp_cb(inst->interface, mac_pkt, NULL, MAC_RADIO_SUCCESS);

            // Remove the packet from the map
            int32_t res = unTrackMacPktByItem(&inst->track_map, track_item);
            if (res != STATIC_MAP_SUCCESS) {
                return res;
            }
        } break;
        case MAC_RADIO_ACK_PKT:
            // Fall through
        default:
            // This is an acknowlagement sent on an unkonwn msg_id
            LOG("BAD ACK, this packet should not be acked\n");
            // TODO this is not actually an error but for now we need to know
            return MAC_RADIO_UNKONWN_ACK;
    }

    return cb_retval;
}

static int32_t manageClosePkt(macRadio_t * inst, macRadioPktTrackItem_t * track_item)  {
    if (track_item != NULL) {
        // It is not valid to get a CLOSE as a response to this packet
        // TODO we should manage this instead of returning an error.
        return MAC_RADIO_INVALID_ERROR;
    }

    // We where told to cancel the connection, set the state to disconnected for all connections
    // TODO we might have to manage each connection differently here
    int32_t res = staticMapForEach(&inst->connections, connItemDisconnectCb);
    if (res != STATIC_MAP_SUCCESS) {
        return res;
    }

    // TODO what if we are waiting to send and receive a reliable packet

    switch(inst->mode) {
        case MAC_RADIO_PERIPHERAL: {
#ifdef MAC_RADIO_MODE_DBG_LED
        gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

            // Return the phy to scan mode
            int32_t res = phyRadioSetScanMode(&inst->phy_instance, 0);
            if (res != PHY_RADIO_SUCCESS) {
                return res;
            }
            LOG("Explicit disconnect requested\n");
        } break;
        case MAC_RADIO_AUTO_MODE: {
#ifdef MAC_RADIO_MODE_DBG_LED
        gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

            // Restart scan mode
            int32_t res = phyRadioSetScanMode(&inst->phy_instance, (rand() % MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS) + MAC_RADIO_MIN_SCAN_TIMEOUT_MS);

            if (res != PHY_RADIO_SUCCESS) {
                return res;
            }
        } break;
        case MAC_RADIO_IDLE:
        case MAC_RADIO_CENTRAL:
        default:
            LOG("Unexpected CLOSE packet\n");
            break;
    }

    return MAC_RADIO_CB_SUCCESS;
}

int32_t managePeripheralSlot(macRadio_t *inst, uint8_t slot, macRadioConnItem_t* peripheral_conn) {
    if (slot < 1 || slot > inst->current_config.num_data_slots) {
        return MAC_RADIO_INVALID_ERROR;
    }

    int32_t res = MAC_RADIO_SUCCESS;

    inst->slot_config_data[0] |= 1 << (slot - 1);

    peripheral_conn->target_tx_slot = slot;

    if ((res = phyRadioSetCustomData(&inst->phy_instance, inst->slot_config_data, PHY_RADIO_SYNC_GEN_DATA_SIZE)) != PHY_RADIO_SUCCESS) {
        return res;
    }

    return MAC_RADIO_SUCCESS;
}


static int32_t phyPacketCallback(phyRadioInterface_t *interface, phyRadioPacket_t *packet) {
    macRadio_t * inst = CONTAINER_OF(interface, macRadio_t, phy_interface);

    int32_t result = cBufferAvailableForRead(packet->pkt_buffer);

    if (result < MAC_RADIO_OVERHEAD_SIZE) {
        LOG("Invalid packet received %i.\n", result);
        return PHY_RADIO_CB_ERROR;
    }

    // Get the packet type
    uint8_t pkt_type = cBufferReadByte(packet->pkt_buffer);

    // Get the packet type
    uint8_t msg_id = cBufferReadByte(packet->pkt_buffer);

    // Check if we are waiting for a response on this package
    macRadioPktTrackItem_t * track_item = findTrackedMacPkt(&inst->track_map, msg_id);

    macRadioPacket_t new_packet = {
        .conn_id    = 0, // TODO what is the conn_id? And specifically what is the conn id before a connection
        .pkt_buffer = packet->pkt_buffer,
        .pkt_type   = pkt_type,
    };

    int32_t cb_retval = MAC_RADIO_CB_SUCCESS;

    switch (pkt_type) {
        case MAC_RADIO_STREAM_PKT:
        case MAC_RADIO_BROADCAST_PKT: {
            // Broadcast and stream packets are accepted by all devices
            macRadioConnItem_t* conn = getConnection(&inst->connections, packet->addr);

            if (conn == NULL || conn->conn_state != MAC_RADIO_CONNECTED) {
                // Mark that this packet comes from an unconnected device
                new_packet.conn_id = 0xFF;
            } else {
                new_packet.conn_id = packet->addr;
            }

            cb_retval = inst->interface->pkt_cb(inst->interface, &new_packet);
           } break;
        case MAC_RADIO_RELIABLE_PKT: {
            macRadioConnItem_t* conn = getConnection(&inst->connections, packet->addr);

            if (conn == NULL || conn->conn_state != MAC_RADIO_CONNECTED) {
                // Only manage these packets from the phy if we are connected
                break;
            }

            // Update the conn_id for this packet
            new_packet.conn_id = packet->addr;

            // Acknowlage this packet
            int32_t res = MAC_RADIO_SUCCESS;
            if ((res = InternalSendOnConnection(inst, MAC_RADIO_ACK_PKT, msg_id, conn->target_addr)) != MAC_RADIO_SUCCESS) {
                return res;
            }
            cb_retval = inst->interface->pkt_cb(inst->interface, &new_packet);
        } break;
        case MAC_RADIO_SYNC_ACK_PKT: {
            // We have received a connect request, manage it

            // Try to create a new connection instance
            macRadioConnItem_t* conn = getOrCreateNewConnection(&inst->connections, packet->addr);

            // We are out of available connections
            if (conn == NULL) {
                LOG("Out of connections!\n");
                return MAC_RADIO_NEW_CONN_ERR;
            }

            int32_t res = MAC_RADIO_SUCCESS;
            if (conn->conn_state != MAC_RADIO_CONNECTED) {
                conn->conn_state = MAC_RADIO_CONNECTED;
                conn->target_addr = packet->addr; // Get the address of requesting device
                LOG_DEBUG("ACK %i\n", packet->addr);

                if ((res = managePeripheralSlot(inst, packet->slot, conn)) != MAC_RADIO_SUCCESS) {
                    // TODO here we might need some cleanup, perhaps a close packet
                    return res;
                }

                if ((res = InternalSendOnConnection(inst, MAC_RADIO_ACK_PKT, msg_id, conn->target_addr)) != MAC_RADIO_SUCCESS) {
                    return res;
                }

                // Trigger connection Callback
                macRadioConn_t new_connection = {
                    .conn_id = packet->addr,
                    .conn_state = MAC_RADIO_CONNECTED,
                };

                // Manage connections
                LOG_DEBUG("Connected as CENTRAL\n");

#ifdef AUTO_SWITCH
                inst->switch_counter = 4;
#endif
                cb_retval = inst->interface->conn_cb(inst->interface, new_connection);
            } else {
                // if we are allready connected, this would indicate that our SYNC_ACK got lost

                // Make sure to clear the TX queue, all packages scheduled are not valid, TODO what about this ..
                // Since the receiver does not concider us connected
                //if ((res = phyRadioClearSlot(&inst->phy_instance, inst->connections.my_tx_slot)) != PHY_RADIO_SUCCESS) {
                //    return res;
                //}

                // Check if this device is still on the same slot
                if (conn->target_tx_slot != packet->slot) {
                    // Clear the slot used by this connection
                    if ((res = clearSlotFromConfig(inst, conn->target_tx_slot)) != MAC_RADIO_SUCCESS) {
                        return res;
                    }

                    // Update the slot used
                    if ((res = managePeripheralSlot(inst, packet->slot, conn)) != MAC_RADIO_SUCCESS) {
                        // TODO here we might need some cleanup, perhaps a close packet
                        return res;
                    }
                }

                // Resend the ack
                if ((res = InternalSendOnConnection(inst, MAC_RADIO_ACK_PKT, msg_id, conn->target_addr)) != MAC_RADIO_SUCCESS) {
                    return res;
                }
            }
        } break;
        case MAC_RADIO_HANDOVER_PKT: {
            macRadioConnItem_t* conn = getConnection(&inst->connections, packet->addr);

            if (conn == NULL || conn->conn_state != MAC_RADIO_CONNECTED) {
                // Check if it is my central that is handing over
                break;
            }

            int32_t res = MAC_RADIO_SUCCESS;
            if ((res = InternalSendOnConnection(inst, MAC_RADIO_ACK_PKT, msg_id, conn->target_addr)) != MAC_RADIO_SUCCESS) {
                return res;
            }

#ifdef MAC_RADIO_MODE_DBG_LED
            gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, true);
#endif /* MAC_RADIO_MODE_DBG_LED */

#ifdef AUTO_SWITCH
            inst->switch_counter = 4;
#endif
            res = phyRadioTransitionPeripheralToCentral(&inst->phy_instance);
            if (res != PHY_RADIO_SUCCESS) {
                return res;
            }
        } break;
        case MAC_RADIO_ACK_PKT: {
            cb_retval = manageAckPkt(inst, packet->addr, track_item);
        } break;
        case MAC_RADIO_KEEP_ALIVE_PKT:
            macRadioConnItem_t* conn = getConnection(&inst->connections, packet->addr);

            if (conn == NULL || conn->conn_state != MAC_RADIO_CONNECTED) {
                // This indicates that another device tries to communicate with us without an active connection
                // Request an explicit disconnect
                int32_t res = MAC_RADIO_SUCCESS;
                if ((res = InternalSendOnConnection(inst, MAC_RADIO_CLOSE_PKT, msg_id, packet->addr)) != MAC_RADIO_SUCCESS) {
                    return res;
                }
                LOG_DEBUG("Unconnected keep alive\n");
            }
            break;
        case MAC_RADIO_CLOSE_PKT:
            cb_retval = manageClosePkt(inst, track_item);
            break;
        default:
            // No other packet is currently supported
            // It would indicate that the contents of the packet was corrupt or mangled by lower layers
            LOG("Invalid packet type %u\n", pkt_type);

            int32_t result = cBufferClear(packet->pkt_buffer);

            if (result != C_BUFFER_SUCCESS) {
                return result; // Fatal error
            }

            return PHY_RADIO_CB_SUCCESS;
    }

    if (cb_retval != MAC_RADIO_CB_SUCCESS) {
        return cb_retval;
    }

    macRadioConnItem_t* conn = getConnection(&inst->connections, packet->addr);

    // Reset the timeout counter for the active connection
    if (conn != NULL && conn->conn_state == MAC_RADIO_CONNECTED) {
        conn->last_heard = 0;
    }

    return PHY_RADIO_CB_SUCCESS;
}

static int32_t InternalSendOnConnection(macRadio_t *inst, macRadioPacketType_t packet_type, uint8_t use_msg_id, uint8_t target_addr) {
    if (inst == NULL) {
        return MAC_RADIO_NULL_ERROR;
    }

    int32_t res = MAC_RADIO_SUCCESS;

    // Aquire a new packet from the internal pool
    macRadioBufferPoolItem_t * buffer_item = aquireBuffer(inst);

    if (buffer_item == NULL) {
        return MAC_RADIO_BUFFER_ERROR;
    }

    cBuffer_t *pkt_buffer = &buffer_item->msg_buf;
    buffer_item->mac_pkt.pkt_type = packet_type;
    buffer_item->mac_pkt.conn_id  = target_addr;

    // Make sure the buffer is fresh and empty
    cBufferClear(pkt_buffer);

    // Generate a new message ID
    inst->msg_id++; // Yes this will loop around, it is the intended behaviour
    uint8_t msg_id = inst->msg_id;

    // TODO This is a bit clunky
    if (packet_type == MAC_RADIO_ACK_PKT) {
        msg_id = use_msg_id;
    }

    bool this_frame = false;

    macRadioPktTrackItem_t* track_item = NULL;
    switch(packet_type) {
        case MAC_RADIO_RELIABLE_PKT:
        case MAC_RADIO_HANDOVER_PKT:
        case MAC_RADIO_SYNC_ACK_PKT:
            // This packet should be sent this frame
            this_frame = true;

            // Keep track of this packet, wait for acknowlagement
            track_item = trackMacPacket(&inst->track_map, &buffer_item->mac_pkt, msg_id);
            if (track_item == NULL) {
                // If the buffer is full or any other error stop here
                return res;
            }
            track_item->internal = true;
            break;
        case MAC_RADIO_ACK_PKT:
        case MAC_RADIO_KEEP_ALIVE_PKT:
        case MAC_RADIO_STREAM_PKT:
        case MAC_RADIO_CLOSE_PKT:
        case MAC_RADIO_BROADCAST_PKT:
            break;
        default:
            return MAC_RADIO_INVALID_ERROR;
    }

    if ((res = cBufferPrependByte(pkt_buffer, msg_id)) != MAC_RADIO_PKT_TYPE_SIZE) {
        // If the buffer is full or any other error stop here
        return MAC_RADIO_BUFFER_ERROR;
    }

    // Prepend the packet type
    if ((res = cBufferPrependByte(pkt_buffer, packet_type)) != MAC_RADIO_PKT_TYPE_SIZE) {
        // If the buffer is full or any other error stop here
        return MAC_RADIO_BUFFER_ERROR;
    }

    // Get a packet from the available pool
    macRadioPktPoolItem_t *packet_item = aquirePacket(inst);
    if (packet_item == NULL) {
        LOG("pool err\n");
        return MAC_RADIO_POOL_ERROR;
    }

    // Configure the mac_pkt
    packet_item->mac_pkt  = &buffer_item->mac_pkt;

    // Mark this packet as internal
    packet_item->internal = true;
    packet_item->msg_id   = msg_id;

    phyRadioPacket_t *new_packet = &packet_item->packet;

    new_packet->addr       = target_addr;
    new_packet->pkt_buffer = pkt_buffer;
    new_packet->slot       = inst->my_tx_slot;
    new_packet->type       = PHY_RADIO_PKT_DIRECT;

    // Send the packet, if the tx queue is full errors will be returned
    res = phyRadioSendOnSlot(&inst->phy_instance, new_packet, this_frame);

    if (res != PHY_RADIO_SUCCESS) {
        // Release all allocated resources
        int32_t result = MAC_RADIO_SUCCESS;
        if ((result = releasePacketByPhy(inst, new_packet)) != STATIC_POOL_SUCCESS) {
            return MAC_RADIO_BUFFER_ERROR;
        }

        if ((result = releaseBufferByMac(inst, &buffer_item->mac_pkt)) != STATIC_POOL_SUCCESS) {
            return MAC_RADIO_BUFFER_ERROR;
        }

        if (track_item != NULL) {
            if ((result = unTrackMacPktByItem(&inst->track_map, track_item)) != STATIC_POOL_SUCCESS) {
                return MAC_RADIO_MAP_ERROR;
            }
        }

        return res;
    } else if (track_item != NULL) {
        track_item->phy_pkt = new_packet;
    }

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioDeInit(macRadio_t *inst) {
    int32_t res = MAC_RADIO_SUCCESS;

    if ((res = phyRadioDeInit(&inst->phy_instance)) != PHY_RADIO_SUCCESS) {
        LOG("Failed to deinit phy radio\n");
    }

    memset(inst, 0, sizeof(macRadio_t));

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioInit(macRadio_t *inst, macRadioConfig_t config, macRadioInterface_t *interface) {
    if (inst == NULL ||
        interface == NULL ||
        interface->conn_cb == NULL ||
        interface->pkt_cb  == NULL ||
        interface->sent_cb == NULL ||
        interface->resp_cb == NULL)
    {

        return MAC_RADIO_NULL_ERROR;
    }

#ifdef MAC_RADIO_MODE_DBG_LED
    gpio_init(MAC_RADIO_MODE_DBG_LED_PIN);
    gpio_set_dir(MAC_RADIO_MODE_DBG_LED_PIN, GPIO_OUT);
#endif /* MAC_RADIO_MODE_DBG_LED */

    // Make sure that the entire memory area is correctly initialized to 0
    memset(inst, 0, sizeof(macRadio_t));

    inst->current_config = config;
    inst->interface      = interface;

    // Set the first msg ID to 0
    inst->msg_id = 0;
    inst->auto_counter = 0;
    inst->switch_counter = 0;

    // Seed the random generator with address and current time
    srand(config.my_address + (unsigned)time_us_64());

    // Initialize the internal buffer pool, and fill it with available buffer items
    for (int32_t i = 0; i < MAC_RADIO_POOL_SIZE; i++) {
        // Initialize the buffer inside of each pool item
        if(cBufferInit(&inst->_buffer_pkt_pool[i].msg_buf, inst->_buffer_pkt_pool[i]._msg_array, MAC_RADIO_INTERNAL_MSG_BUFFER_SIZE) != C_BUFFER_SUCCESS) {
            return MAC_RADIO_BUFFER_ERROR;
        }

        // Populate the buffer in the mac_pkt
        inst->_buffer_pkt_pool[i].mac_pkt.pkt_buffer = &inst->_buffer_pkt_pool[i].msg_buf;
    }

    int32_t res = STATIC_POOL_INIT(inst->buffer_packet_pool, inst->_buffer_pool_array, MAC_RADIO_POOL_SIZE, inst->_buffer_pkt_pool);
    if (res != STATIC_POOL_SUCCESS) {
        return MAC_RADIO_POOL_ERROR;
    }

    // Initialize the packet pool, and fill it with available packets
    res = STATIC_POOL_INIT(inst->packet_pool, inst->_pool_array, MAC_RADIO_POOL_SIZE, inst->_pkt_pool);
    if (res != STATIC_POOL_SUCCESS) {
        return MAC_RADIO_POOL_ERROR;
    }

    // Initialize the static map used to keep track of connections
    res = STATIC_MAP_INIT(inst->connections, inst->_array, MAC_RADIO_MAX_NUM_CONNECTIONS, inst->_con_items);
    if (res != STATIC_MAP_SUCCESS) {
        return MAC_RADIO_MAP_ERROR;
    }

    // Initialize the static map used to keep track of relieable packets
    res = STATIC_MAP_INIT(inst->track_map, inst->_map_array, MAC_RADIO_MAP_SIZE, inst->_track_map_array);

    if (res != STATIC_MAP_SUCCESS) {
        return MAC_RADIO_MAP_ERROR;
    }

    // Configure the phy interface
    inst->phy_interface.packet_cb     = phyPacketCallback;
    inst->phy_interface.sent_cb       = phyPacketSent;
    inst->phy_interface.sync_state_cb = phySyncStateCb;

    // Initialize the phy radio
    if ((res = phyRadioInit(&inst->phy_instance, &inst->phy_interface, config.my_address)) != PHY_RADIO_SUCCESS) {
        return res;
    }

    // Configure the TDMA frame
    inst->frame_config.frame_length_us = 0; // Automatically updated by lower layer
    // The number of slots is one for the sync and then N data slots
    inst->frame_config.num_slots       = 1 + inst->current_config.num_data_slots;

    // Configure the time intervals of each slot
    for (uint32_t i = 0; i < inst->frame_config.num_slots; i++) {
        // Speciall config for the sync slot
        if (i == 0) {
            inst->frame_config.slots[i].slot_start_guard_us = PHY_RADIO_SLOT_GUARD_TIME_US;
            inst->frame_config.slots[i].slot_length_us      = PHY_RADIO_ACTIVE_SYNC_SLOT_TIME_US;
            inst->frame_config.slots[i].slot_end_guard_us   = 0; // Not yet supported
        } else {
            inst->frame_config.slots[i].slot_start_guard_us = PHY_RADIO_SLOT_GUARD_TIME_US;
            inst->frame_config.slots[i].slot_length_us      = PHY_RADIO_ACTIVE_SLOT_TIME_US;
            inst->frame_config.slots[i].slot_end_guard_us   = 0; // Not yet supported
        }
    }
    // Set the interval and end guard
    inst->frame_config.sync_interval     = MAC_RADIO_SYNC_INTERVAL;
    inst->frame_config.end_guard         = PHY_RADIO_FRAME_GUARD_US;
    inst->frame_config.slot_end_guard_us = PHY_RADIO_SLOT_END_GUARD_US;

    // Configure TDMA frame, note that the casting from const to non const here is not great
    if ((res = phyRadioSetFrameStructure(&inst->phy_instance, &inst->frame_config)) != PHY_RADIO_SUCCESS) {
        LOG("RADIO FRAME CONFIG FAILED! %i\n", res);
        return res;
    }

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioEventInQueue(macRadio_t *inst) {
    if (phyRadioEventInQueue(&inst->phy_instance) > 0) {
        return MAC_RADIO_INTERRUPT_IN_QUEUE;
    }

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioProcess(macRadio_t *inst) {
    return phyRadioProcess(&inst->phy_instance);
}

int32_t macRadioSetAutoMode(macRadio_t *inst) {
    // Manage the current mode
    switch(inst->mode) {
        case MAC_RADIO_CENTRAL:
        case MAC_RADIO_PERIPHERAL: {
            // Make sure to trigger a disconnect if we are connected
            int32_t res = staticMapForEach(&inst->connections, connItemDisconnectCb);
            if (res != STATIC_MAP_SUCCESS) {
                return res;
            }
       } break;
        case MAC_RADIO_AUTO_MODE:
            return MAC_RADIO_SUCCESS;
        default:
            break;
    }

    // Init the auto mode counter to a random value
    inst->auto_counter = (uint8_t)(rand() % MAC_RADIO_DEFAULT_NUM_BEACONS) + MAC_RADIO_MIN_NUM_BEACONS;

#ifdef MAC_RADIO_MODE_DBG_LED
    gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

    // Reset the slot config
    for (int32_t i = 0; i < PHY_RADIO_SYNC_GEN_DATA_SIZE; i++) {
        inst->slot_config_data[i] = 0x00;
    }

    // Allways start in scan
    int32_t res = phyRadioSetScanMode(&inst->phy_instance, (rand() % MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS) + MAC_RADIO_MIN_SCAN_TIMEOUT_MS);

    if (res != PHY_RADIO_SUCCESS) {
        return res;
    }

    inst->mode = MAC_RADIO_AUTO_MODE;

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioSetCentralMode(macRadio_t *inst) {
    // Manage the current mode
    switch(inst->mode) {
        case MAC_RADIO_PERIPHERAL:
        case MAC_RADIO_AUTO_MODE: {
            // Make sure to trigger a disconnect if we are connected
            int32_t res = staticMapForEach(&inst->connections, connItemDisconnectCb);
            if (res != STATIC_MAP_SUCCESS) {
                return res;
            }
        } break;
        case MAC_RADIO_CENTRAL:
            return MAC_RADIO_SUCCESS;
        default:
            break;
    }

#ifdef MAC_RADIO_MODE_DBG_LED
        gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, true);
#endif /* MAC_RADIO_MODE_DBG_LED */

    // Reset the slot config
    for (int32_t i = 0; i < PHY_RADIO_SYNC_GEN_DATA_SIZE; i++) {
        inst->slot_config_data[i] = 0x00;
    }

    int32_t res = phyRadioSetCentralMode(&inst->phy_instance);
    if (res != PHY_RADIO_SUCCESS) {
        return res;
    }

    // Configure the central to use slot
    if ((res = setCentralSlot(inst, MAC_RADIO_CENTRAL_SLOT)) != MAC_RADIO_SUCCESS) {
        return res;
    }

    // Set all slots as available in the sync message
    res = phyRadioSetCustomData(&inst->phy_instance, inst->slot_config_data, PHY_RADIO_SYNC_GEN_DATA_SIZE);

    res = configureMySlots(inst);
    if (res != MAC_RADIO_SUCCESS) {
        return res;
    }

    inst->mode = MAC_RADIO_CENTRAL;

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioSetPeripheralMode(macRadio_t *inst) {
    // Manage the current mode
    switch(inst->mode) {
        case MAC_RADIO_CENTRAL:
        case MAC_RADIO_AUTO_MODE: {
            // Make sure to trigger a disconnect if we are connected
            int32_t res = staticMapForEach(&inst->connections, connItemDisconnectCb);
            if (res != STATIC_MAP_SUCCESS) {
                return res;
            }
        } break;
        case MAC_RADIO_PERIPHERAL:
            return MAC_RADIO_SUCCESS;
        default:
            break;
    }

#ifdef MAC_RADIO_MODE_DBG_LED
    gpio_put(MAC_RADIO_MODE_DBG_LED_PIN, false);
#endif /* MAC_RADIO_MODE_DBG_LED */

    // Reset the slot config
    for (int32_t i = 0; i < PHY_RADIO_SYNC_GEN_DATA_SIZE; i++) {
        inst->slot_config_data[i] = 0x00;
    }

    int32_t res = phyRadioSetScanMode(&inst->phy_instance, 0);

    if (res != PHY_RADIO_SUCCESS) {
        return res;
    }

    res = configureMySlots(inst);
    if (res != MAC_RADIO_SUCCESS) {
        return res;
    }

    inst->mode = MAC_RADIO_PERIPHERAL;

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioSendOnConnection(macRadio_t *inst, macRadioPacket_t *packet) {
    if (inst == NULL || packet == NULL) {
        return MAC_RADIO_NULL_ERROR;
    }

    // Find the connection
    macRadioConnItem_t* conn = getConnection(&inst->connections, packet->conn_id);
    uint32_t target_addr = 0;

    // Check if this connection exists
    if (conn == NULL) {
        int32_t num_conns = staticMapGetNumItems(&inst->connections);
        if (num_conns == 0 || packet->pkt_type != MAC_RADIO_BROADCAST_PKT) {
            return MAC_RADIO_NO_CONN_ERROR;
        }
    } else if (conn->conn_state != MAC_RADIO_CONNECTED) {
            return MAC_RADIO_NO_CONN_ERROR;
    } else {
        target_addr = conn->target_addr;
    }

    int32_t res = MAC_RADIO_SUCCESS;

    // Generate a new msg_id for this packet
    inst->msg_id++; // Yes this will loop around, it is the intended behaviour

    macRadioPktTrackItem_t* track_item = NULL;
    switch(packet->pkt_type) {
        case MAC_RADIO_RELIABLE_PKT:
           // Keep track of this packet, wait for acknowlagement
            track_item = trackMacPacket(&inst->track_map, packet, inst->msg_id);
            if (track_item == NULL) {
                // If the buffer is full or any other error stop here
                return res;
            }
            break;
        case MAC_RADIO_ACK_PKT:
        case MAC_RADIO_STREAM_PKT:
        case MAC_RADIO_BROADCAST_PKT:
        break;
        default:
            return MAC_RADIO_INVALID_ERROR;
    }

    // Prepend a new message ID for this packet
    if ((res = cBufferPrependByte(packet->pkt_buffer, inst->msg_id)) != MAC_RADIO_PKT_TYPE_SIZE) {
        // If the buffer is full or any other error stop here
        return MAC_RADIO_BUFFER_ERROR;
    }

    // Prepend the packet type
    if ((res = cBufferPrependByte(packet->pkt_buffer, packet->pkt_type)) != MAC_RADIO_PKT_TYPE_SIZE) {
        // If the buffer is full or any other error stop here
        return MAC_RADIO_BUFFER_ERROR;
    }

    // Get a packet from the available pool
    macRadioPktPoolItem_t *packet_item = aquirePacket(inst);
    if (packet_item == NULL) {
        // TODO, What should we do with allocated resources
        return MAC_RADIO_POOL_ERROR;
    }

    // Store the pointer to the original packet
    packet_item->mac_pkt = packet;

    // This is not an internal package
    packet_item->internal = false;
    packet_item->msg_id   = inst->msg_id;

    phyRadioPacket_t *new_packet = &packet_item->packet;

    new_packet->addr       = target_addr;
    new_packet->pkt_buffer = packet->pkt_buffer;
    new_packet->slot       = inst->my_tx_slot;

    // Manage packet type
    switch (packet->pkt_type) {
        case MAC_RADIO_STREAM_PKT:
        case MAC_RADIO_BROADCAST_PKT:
            new_packet->type = PHY_RADIO_PKT_BROADCAST;
            break;
        default:
            new_packet->type = PHY_RADIO_PKT_DIRECT;
            break;
    }

    // Send the packet, if the tx queue is full errors will be returned
    res = phyRadioSendOnSlot(&inst->phy_instance, new_packet, false);
    if (res != PHY_RADIO_SUCCESS) {
        // Release all allocated resources
        int32_t result = MAC_RADIO_SUCCESS;
        if ((result = releasePacketByPhy(inst, new_packet)) != STATIC_POOL_SUCCESS) {
            return MAC_RADIO_BUFFER_ERROR;
        }

        if (track_item != NULL) {
            if ((result = unTrackMacPktByItem(&inst->track_map, track_item)) != STATIC_MAP_SUCCESS) {
                return MAC_RADIO_MAP_ERROR;
            }
        }

        return res;
    } else if (track_item != NULL) {
        track_item->phy_pkt = new_packet;
    }

    return res;
}


int32_t macRadioSwitchCentral(macRadio_t *inst, uint8_t next_central_addr) {
    if (inst == NULL) {
        return MAC_RADIO_NULL_ERROR;
    }

    // Switch to scan mode, try to handover
    int32_t res = InternalSendOnConnection(inst, MAC_RADIO_HANDOVER_PKT, 0, next_central_addr);

    if (res != MAC_RADIO_SUCCESS) {
        return res;
    }

    inst->central_addr = next_central_addr;

    return MAC_RADIO_SUCCESS;
}
