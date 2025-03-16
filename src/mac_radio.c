/**
 * @file:       mac_radio.c
 * @author:     Lucas Wennerholm <lucas.wennerholm@gmail.com>
 * @brief:      Implementation of radio mac layer
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

#include "mac_radio.h"
#include <string.h>
#include <stdlib.h>

#define DEFAULT_TTL 1

#ifndef LOG
#define LOG(f_, ...) printf((f_), ##__VA_ARGS__)
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG(f_, ...)//printf((f_), ##__VA_ARGS__)
#endif

#ifndef LOG_V_DEBUG
#define LOG_V_DEBUG(f_, ...)// printf((f_), ##__VA_ARGS__)
#endif

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#define MAC_RADIO_DEFAULT_NUM_BEACONS     (8)
#define MAC_RADIO_MIN_NUM_BEACONS         (2)
#define MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS (2*PHY_RADIO_SUPERFRAME_TIME_MS)
#define MAC_RADIO_MIN_SCAN_TIMEOUT_MS     (PHY_RADIO_SUPERFRAME_TIME_MS)

static int32_t InternalSendOnConnection(macRadio_t *inst, macRadioPacketType_t packet_type, uint8_t use_msg_id);

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

static int32_t disconnectAndNotify(macRadio_t *inst) {
        inst->connections.conn_state = MAC_RADIO_DISCONNECTED;

        // Trigger connection Callback
        macRadioConn_t new_connection = {
            .conn_id = 0, // TODO manage handout of connID's
            .conn_state = MAC_RADIO_DISCONNECTED,
        };

        // Re-Init the auto mode counter to a random value
        inst->auto_counter = (uint8_t)(rand() % MAC_RADIO_DEFAULT_NUM_BEACONS) + MAC_RADIO_MIN_NUM_BEACONS;

        // TODO manage connections
        return inst->interface->conn_cb(inst->interface, new_connection);
}

static int32_t manageCentralSyncSent(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // The radio is successfully configured as a central device
    inst->connections.my_tx_slot  = sync_state->tx_slot_number;
    inst->connections.last_heard++;

    // Check if the connection has timed out
    if (inst->connections.last_heard > MAC_RADIO_SYNC_TIMEOUT && inst->connections.conn_state == MAC_RADIO_CONNECTED) {
        // Connection lost
        int32_t cb_retval = disconnectAndNotify(inst);
        if (cb_retval != MAC_RADIO_CB_SUCCESS) {
            return cb_retval;
        }

        if (inst->mode == MAC_RADIO_AUTO_MODE) {
            // If we are in auto mode return to scan on disconnect
            int32_t res = phyRadioSetScanMode(&inst->phy_instance, (rand() % MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS) + MAC_RADIO_MIN_SCAN_TIMEOUT_MS);
            if (res != PHY_RADIO_SUCCESS) {
                return res;
            }
        }
    } else if (inst->mode == MAC_RADIO_AUTO_MODE && inst->connections.conn_state != MAC_RADIO_CONNECTED) {
        // Check if it is time to switch mode
        if (inst->auto_counter == 0) {
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

    // TODO what happens if this callback comes when we are waiting for a reliable packet?
    return PHY_RADIO_CB_SUCCESS;
}

static int32_t managePeripheralFirstSync(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // New sync detected
    inst->connections.conn_state  = MAC_RADIO_CONNECTING;

    // Store the central address and my assigned TX slot
    inst->connections.target_addr = sync_state->central_address;
    inst->connections.my_tx_slot  = sync_state->tx_slot_number;

    // Trigger a connect request
    int32_t res = InternalSendOnConnection(inst, MAC_RADIO_SYNC_ACK_PKT, 0);
    if (res != MAC_RADIO_SUCCESS) {
        return res;
    }

    // Inform the phy layer to enter peripheral mode
    return PHY_RADIO_CB_SET_PERIPHERAL;
}

static int32_t managePeripheralReSync(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // Check if we have allready tried to connect
    if (inst->connections.conn_state == MAC_RADIO_CONNECTING) {
        // Our last synack must have gotten lost, retrigger connect
        return managePeripheralFirstSync(inst, sync_state);
    }

    // If we are connected send a keep alive, to notify the central that we exist
    if (inst->connections.conn_state == MAC_RADIO_CONNECTED) {
        // Trigger an alive packet
        int32_t res = MAC_RADIO_SUCCESS;
        if ((res = InternalSendOnConnection(inst, MAC_RADIO_KEEP_ALIVE_PKT, 0)) != MAC_RADIO_SUCCESS) {
            return res;
        }
    }

    // Inform the phy to stay in current mode
    return PHY_RADIO_CB_SUCCESS;
}

static int32_t managePeripheralSyncLost(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // Sync was lost, set the state to disconnected
    if (inst->connections.conn_state == MAC_RADIO_CONNECTED) {
        int32_t cb_retval = disconnectAndNotify(inst);
        if (cb_retval != MAC_RADIO_CB_SUCCESS) {
            return cb_retval;
        }
    }

    // Manage auto mode
    if (inst->mode == MAC_RADIO_AUTO_MODE) {
        // If we are in auto mode return to scan on disconnect
        int32_t res = phyRadioSetScanMode(&inst->phy_instance, (rand() % MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS) + MAC_RADIO_MIN_SCAN_TIMEOUT_MS);
        if (res != PHY_RADIO_SUCCESS) {
            return res;
        }
        return PHY_RADIO_CB_SUCCESS;
    }

    // TODO what happens if this callback comes when we are waiting for a reliable packet?
    // Inform the phy layer to return to scan mode
    return PHY_RADIO_CB_SET_SCAN;
}

static int32_t mapItemCb(staticMap_t *map, staticMapItem_t *map_item) {
    macRadioPktTrackItem_t * track_item = CONTAINER_OF(map_item, macRadioPktTrackItem_t, node);
    macRadio_t * inst = CONTAINER_OF(map, macRadio_t, track_map);

    if (track_item->ttl == 0) {
        // Check if it is an external or internal packet that has timed out
        if (track_item->internal) {
            // Release buffers used by internal packets
            int32_t res = releaseBufferByMac(inst, track_item->mac_pkt);
            if (res != STATIC_POOL_SUCCESS) {
                // Fatal, something is very bad
                return res;
            }

            // TODO should we do something specific when an internal packet times out?
            // Currently we risk getting stuck in CONNECTING state ..

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

static int32_t managePhyRxSlotStart(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // We use this notification to manage packet timeouts, loop through all active packets
    int32_t res = staticMapForEach(&inst->track_map, mapItemCb);
    if (res != STATIC_MAP_SUCCESS) {
        return res;
    }

    return PHY_RADIO_CB_SUCCESS;
}

static int32_t manageCentralConflictingSync(macRadio_t *inst, const phyRadioSyncState_t *sync_state) {
    // Switch mode, TODO perhpas we need to notify about this
    switch(inst->mode) {
        case MAC_RADIO_CENTRAL:
            // If I was configured to be central go to peripheral mode
            inst->mode = MAC_RADIO_PERIPHERAL;
            break;
        case MAC_RADIO_PERIPHERAL:
        case MAC_RADIO_AUTO_MODE:
            break;
        default:
            break;
    }

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

    // Switch to central mode
    int32_t res = phyRadioSetCentralMode(&inst->phy_instance);
    if (res != PHY_RADIO_SUCCESS) {
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
        case PHY_RADIO_RX_SLOT_START:
            return managePhyRxSlotStart(inst, sync_state);
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

    if (res != MAC_RADIO_SUCCESS) {
        // If this fails something is very broken
        LOG("Failed to return packet to POOL\n");
        return inst->interface->sent_cb(inst->interface, mac_pkt, MAC_RADIO_POOL_ERROR);
    }

    macRadioPktTrackItem_t *track_item = NULL;
    switch(mac_pkt->pkt_type) {
        case MAC_RADIO_SYNC_ACK_PKT:
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
                    if ((res = releaseBufferByBuf(inst, packet->pkt_buffer) != STATIC_POOL_SUCCESS)) {
                        // This is a fatal error, something is very bad
                        LOG("Failed to return buffer to POOL\n");
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
                if ((res = releaseBufferByBuf(inst, packet->pkt_buffer) != STATIC_POOL_SUCCESS)) {
                    // Fatal, this would be very bad
                    LOG("Failed to return buffer to POOL\n");
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

static int32_t manageAckPkt(macRadio_t * inst, macRadioPktTrackItem_t * track_item)  {
    if (track_item == NULL) {
        // This is an acknowlagement sent on an unkonwn msg_id
        LOG("BAD ACK, unknown response\n");
        // Most likely this is a message that has allready timed out
        return MAC_RADIO_CB_SUCCESS;
    }

    int32_t cb_retval = MAC_RADIO_CB_SUCCESS;

    // Get the original packet sent
    macRadioPacket_t *mac_pkt = track_item->mac_pkt;

    // Manage the tracked packet type
    switch (mac_pkt->pkt_type) {
        case MAC_RADIO_SYNC_ACK_PKT: {
            int32_t res = MAC_RADIO_SUCCESS;
            // Release the internal buffer used for this message, MAC_RADIO_SYNC_ACK_PKT, is allways internal
            if ((res = releaseBufferByMac(inst, mac_pkt)) != STATIC_POOL_SUCCESS) {
                return res;
            }

            // Remove the packet from the map
            if ((res = unTrackMacPktByItem(&inst->track_map, track_item))!= STATIC_MAP_SUCCESS) {
                return res;
            }

            // The SynAck was Acked, go to connected mode
            if (inst->connections.conn_state == MAC_RADIO_CONNECTING) {
                inst->connections.conn_state = MAC_RADIO_CONNECTED;

                // Trigger connected Callback
                macRadioConn_t new_connection = {
                    .conn_id = 0, // TODO manage handout of connID's
                    .conn_state = MAC_RADIO_CONNECTED,
                };

                // Manage connections
                LOG_DEBUG("Connected as PERIPHERAL\n");
                cb_retval = inst->interface->conn_cb(inst->interface, new_connection);
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

    int32_t cb_retval = disconnectAndNotify(inst);
    if (cb_retval != MAC_RADIO_CB_SUCCESS) {
        return cb_retval;
    }

    switch(inst->mode) {
        case MAC_RADIO_PERIPHERAL: {
            // Return the phy to scan mode
            int32_t res = phyRadioSetScanMode(&inst->phy_instance, 0);
            if (res != PHY_RADIO_SUCCESS) {
                return res;
            }
            LOG("Explicit disconnect requested\n");
        } break;
        case MAC_RADIO_AUTO_MODE: {
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
        .conn_id    = 0, // TODO what is the conn_id?
        .pkt_buffer = packet->pkt_buffer,
        .pkt_type   = pkt_type,
    };

    int32_t cb_retval = MAC_RADIO_CB_SUCCESS;

    switch (pkt_type) {
        case MAC_RADIO_STREAM_PKT:
        case MAC_RADIO_BROADCAST_PKT:
            if (inst->connections.conn_state != MAC_RADIO_CONNECTED) {
                // Only manage these packets from the phy if we are connected
                break;
            }

            cb_retval = inst->interface->pkt_cb(inst->interface, &new_packet);
            break;
        case MAC_RADIO_RELIABLE_PKT: {
            if (inst->connections.conn_state != MAC_RADIO_CONNECTED) {
                // Only manage these packets from the phy if we are connected
                break;
            }

            // Acknowlage this packet
            int32_t res = MAC_RADIO_SUCCESS;
            if ((res = InternalSendOnConnection(inst, MAC_RADIO_ACK_PKT, msg_id)) != MAC_RADIO_SUCCESS) {
                return res;
            }
            cb_retval = inst->interface->pkt_cb(inst->interface, &new_packet);
        } break;
        case MAC_RADIO_SYNC_ACK_PKT: {
            // We have received a connect request, manage it
            inst->connections.conn_state = MAC_RADIO_CONNECTED;
            inst->connections.target_addr = packet->addr; // Get the address of requesting device

            int32_t res = MAC_RADIO_SUCCESS;
            if ((res = InternalSendOnConnection(inst, MAC_RADIO_ACK_PKT, msg_id)) != MAC_RADIO_SUCCESS) {
                return res;
            }

            // Trigger connection Callback
            macRadioConn_t new_connection = {
                .conn_id = 0, // TODO manage handout of connID's
                .conn_state = MAC_RADIO_CONNECTED,
            };

            // Manage connections
            LOG_DEBUG("Connected as CENTRAL\n");
            cb_retval = inst->interface->conn_cb(inst->interface, new_connection);
        } break;
        case MAC_RADIO_ACK_PKT: {
            cb_retval = manageAckPkt(inst, track_item);
        } break;
        case MAC_RADIO_KEEP_ALIVE_PKT:
            if (inst->connections.conn_state != MAC_RADIO_CONNECTED) {
                // This indicates that another device tries to communicate with us without an active connection
                // Request an explicit disconnect
                int32_t res = MAC_RADIO_SUCCESS;
                if ((res = InternalSendOnConnection(inst, MAC_RADIO_CLOSE_PKT, msg_id)) != MAC_RADIO_SUCCESS) {
                    return res;
                }
                LOG("Unconnected keep alive\n");
            }
            break;
        case MAC_RADIO_CLOSE_PKT:
            cb_retval = manageClosePkt(inst, track_item);
            break;
        default:
            // No other packet is currently supported
            return PHY_RADIO_CB_ERROR;
    }

    if (cb_retval != MAC_RADIO_CB_SUCCESS) {
        return cb_retval;
    }

    // Reset the timeout counter
    inst->connections.last_heard = 0;

    return PHY_RADIO_CB_SUCCESS;
}

static int32_t InternalSendOnConnection(macRadio_t *inst, macRadioPacketType_t packet_type, uint8_t use_msg_id) {
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

    // Make sure the buffer is fresh and empty
    cBufferClear(pkt_buffer);

    // TODO manage the conn_id here

    // Generate a new message ID
    inst->msg_id++; // Yes this will loop around, it is the intended behaviour
    uint8_t msg_id = inst->msg_id;

    // TODO This is a bit clunky
    if (packet_type == MAC_RADIO_ACK_PKT) {
        msg_id = use_msg_id;
    }

    macRadioPktTrackItem_t* track_item = NULL;
    switch(packet_type) {
        case MAC_RADIO_RELIABLE_PKT:
        case MAC_RADIO_SYNC_ACK_PKT:
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
        return MAC_RADIO_POOL_ERROR;
    }

    // Configure the mac_pkt
    packet_item->mac_pkt  = &buffer_item->mac_pkt;

    // Mark this packet as internal
    packet_item->internal = true;
    packet_item->msg_id   = msg_id;

    phyRadioPacket_t *new_packet = &packet_item->packet;

    new_packet->addr       = inst->connections.target_addr;
    new_packet->pkt_buffer = pkt_buffer;
    new_packet->slot       = inst->connections.my_tx_slot;
    new_packet->type       = PHY_RADIO_PKT_DIRECT;

    // Send the packet, if the tx queue is full errors will be returned
    res = phyRadioSendOnSlot(&inst->phy_instance, new_packet);
    if (res != PHY_RADIO_SUCCESS) {
        // Release all allocated resources
        int32_t result = MAC_RADIO_SUCCESS;
        if ((result = releasePacketByPhy(inst, new_packet)) != MAC_RADIO_SUCCESS) {
            return MAC_RADIO_BUFFER_ERROR;
        }

        if ((result = releaseBufferByMac(inst, &buffer_item->mac_pkt))) {
            return MAC_RADIO_BUFFER_ERROR;
        }

        if (track_item != NULL) {
            if ((result = unTrackMacPktByItem(&inst->track_map, track_item))) {
                return MAC_RADIO_MAP_ERROR;
            }
        }

        return res;
    }

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

    // Make sure that the entire memory area is correctly initialized to 0
    memset(inst, 0, sizeof(macRadio_t));

    inst->current_config = config;
    inst->interface      = interface;

    int32_t res = MAC_RADIO_SUCCESS;

    // Configure the phy interface
    inst->phy_interface.packet_cb     = phyPacketCallback;
    inst->phy_interface.sent_cb       = phyPacketSent;
    inst->phy_interface.sync_state_cb = phySyncStateCb;

    // Initialize the phy radio
    if ((res = phyRadioInit(&inst->phy_instance, &inst->phy_interface, config.my_address)) != PHY_RADIO_SUCCESS) {
        return res;
    }

    // Set the first msg ID to 0
    inst->msg_id = 0;
    inst->auto_counter = 0;

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

    res = STATIC_POOL_INIT(inst->buffer_packet_pool, inst->_buffer_pool_array, MAC_RADIO_POOL_SIZE, inst->_buffer_pkt_pool);
    if (res != STATIC_POOL_SUCCESS) {
        return MAC_RADIO_POOL_ERROR;
    }

    // Init the connection parameters
    inst->connections.conn_state  = MAC_RADIO_DISCONNECTED;
    inst->connections.last_heard  = 0;
    inst->connections.my_tx_slot  = 0;
    inst->connections.target_addr = 0;

    // Initialize the packet pool, and fill it with available packets
    res = STATIC_POOL_INIT(inst->packet_pool, inst->_pool_array, MAC_RADIO_POOL_SIZE, inst->_pkt_pool);
    if (res != STATIC_POOL_SUCCESS) {
        return MAC_RADIO_POOL_ERROR;
    }

    // Initialize the static map used to keep track of relieable packets
    res = STATIC_MAP_INIT(inst->track_map, inst->_map_array, MAC_RADIO_MAP_SIZE, inst->_track_map_array);

    if (res != STATIC_MAP_SUCCESS) {
        return MAC_RADIO_MAP_ERROR;
    }

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioProcess(macRadio_t *inst) {
    return phyRadioProcess(&inst->phy_instance);
}

int32_t macRadioSetAutoMode(macRadio_t *inst) {
    // Init the auto mode counter to a random value
    inst->auto_counter = (uint8_t)(rand() % MAC_RADIO_DEFAULT_NUM_BEACONS) + MAC_RADIO_MIN_NUM_BEACONS;

    // Randomly select if to start in cental or peripheral mode
    if (inst->auto_counter % 2 == 0) {
        int32_t res = phyRadioSetScanMode(&inst->phy_instance, (rand() % MAC_RADIO_DEFAULT_SCAN_TIMEOUT_MS) + MAC_RADIO_MIN_SCAN_TIMEOUT_MS);

        if (res != PHY_RADIO_SUCCESS) {
            return res;
        }
    } else {
        int32_t res = phyRadioSetCentralMode(&inst->phy_instance);
        if (res != PHY_RADIO_SUCCESS) {
            return res;
        }
    }

    inst->mode = MAC_RADIO_AUTO_MODE;

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioSetCentralMode(macRadio_t *inst) {
    int32_t res = phyRadioSetCentralMode(&inst->phy_instance);
    if (res != PHY_RADIO_SUCCESS) {
        return res;
    }

    inst->mode = MAC_RADIO_CENTRAL;

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioSetPeripheralMode(macRadio_t *inst) {
    int32_t res = phyRadioSetScanMode(&inst->phy_instance, 0);

    if (res != PHY_RADIO_SUCCESS) {
        return res;
    }

    inst->mode = MAC_RADIO_PERIPHERAL;

    return MAC_RADIO_SUCCESS;
}

int32_t macRadioSendOnConnection(macRadio_t *inst, macRadioPacket_t *packet) {
    if (inst == NULL || packet == NULL) {
        return MAC_RADIO_NULL_ERROR;
    }

    // Check that we have a peer to send to
    if (inst->connections.conn_state < MAC_RADIO_CONNECTED) {
        return MAC_RADIO_NO_CONN_ERROR;
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

    new_packet->addr       = inst->connections.target_addr;
    new_packet->pkt_buffer = packet->pkt_buffer;
    new_packet->slot       = inst->connections.my_tx_slot;

    // Manage packet type
    switch (packet->pkt_type) {
        case MAC_RADIO_BROADCAST_PKT:
            new_packet->type = PHY_RADIO_PKT_BROADCAST;
            break;
        default:
            new_packet->type = PHY_RADIO_PKT_DIRECT;
            break;
    }

    // Send the packet, if the tx queue is full errors will be returned
    res = phyRadioSendOnSlot(&inst->phy_instance, new_packet);
    if (res != PHY_RADIO_SUCCESS) {
        // Release all allocated resources
        int32_t result = MAC_RADIO_SUCCESS;
        if ((result = releasePacketByPhy(inst, new_packet)) != MAC_RADIO_SUCCESS) {
            return MAC_RADIO_BUFFER_ERROR;
        }

        if (track_item != NULL) {
            if ((result = unTrackMacPktByItem(&inst->track_map, track_item))) {
                return MAC_RADIO_MAP_ERROR;
            }
        }

        return res;
    }

    return res;
}