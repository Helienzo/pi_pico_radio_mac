/**
 * @file:       logger.c
 * @author:     Lucas Wennerholm <lucas.wennerholm@gmail.com>
 * @brief:      Non-blocking DMA-based UART logger implementation
 *
 * @license: Apache 2.0
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

#include "logger.h"
#include "hardware/uart.h"
#include "hardware/dma.h"
#include "hardware/irq.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// Double buffering for DMA transfers
static char tx_buffer[2][LOGGER_BUFFER_SIZE];
static volatile uint8_t active_buffer = 0;
static int dma_channel = -1;

int loggerInit(void) {
    // Initialize UART
    uart_init(LOGGER_UART_INST, LOGGER_BAUD_RATE);

    // Set TX and RX pins
    gpio_set_function(LOGGER_TX_PIN, GPIO_FUNC_UART);
    gpio_set_function(LOGGER_RX_PIN, GPIO_FUNC_UART);

    // Claim a DMA channel
    dma_channel = dma_claim_unused_channel(true);
    if (dma_channel < 0) {
        return -1;
    }

    // Configure DMA channel
    dma_channel_config c = dma_channel_get_default_config(dma_channel);
    channel_config_set_transfer_data_size(&c, DMA_SIZE_8);
    channel_config_set_read_increment(&c, true);
    channel_config_set_write_increment(&c, false);
    channel_config_set_dreq(&c, uart_get_dreq(LOGGER_UART_INST, true)); // TX DREQ

    dma_channel_configure(
        dma_channel,
        &c,
        &uart_get_hw(LOGGER_UART_INST)->dr,  // Write to UART data register
        NULL,                                  // Read address (set later)
        0,                                     // Transfer count (set later)
        false                                  // Don't start yet
    );

    // No interrupt needed - we'll poll dma_channel_is_busy()

    return 0;
}

bool loggerIsBusy(void) {
    return dma_channel_is_busy(dma_channel);
}

void loggerFlush(void) {
    while (dma_channel_is_busy(dma_channel)) {
        tight_loop_contents();
    }
}

void loggerPrintf(const char *format, ...) {
    // If DMA is still busy, drop this message
    if (dma_channel_is_busy(dma_channel)) {
        return;
    }

    // Select the inactive buffer for formatting
    uint8_t buffer_index = active_buffer;

    // Format the string
    va_list args;
    va_start(args, format);
    int len = vsnprintf(tx_buffer[buffer_index], LOGGER_BUFFER_SIZE, format, args);
    va_end(args);

    // Check if message was truncated
    if (len < 0) {
        return; // Error in formatting
    }

    if (len >= LOGGER_BUFFER_SIZE) {
        len = LOGGER_BUFFER_SIZE - 1; // Truncated
    }

    // Start DMA transfer (non-blocking)
    dma_channel_set_read_addr(dma_channel, tx_buffer[buffer_index], false);
    dma_channel_set_trans_count(dma_channel, len, true); // Start transfer

    // Switch to the other buffer for next call
    active_buffer = 1 - active_buffer;
}
