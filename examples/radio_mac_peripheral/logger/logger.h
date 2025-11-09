/**
 * @file:       logger.h
 * @author:     Lucas Wennerholm <lucas.wennerholm@gmail.com>
 * @brief:      Non-blocking DMA-based UART logger
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

#ifndef LOGGER_H
#define LOGGER_H

#include "pico/stdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LOGGER_UART_INST
#define LOGGER_UART_INST uart0
#endif

#ifndef LOGGER_BAUD_RATE
#define LOGGER_BAUD_RATE 115200
#endif

#ifndef LOGGER_TX_PIN
#define LOGGER_TX_PIN 0
#endif

#ifndef LOGGER_RX_PIN
#define LOGGER_RX_PIN 1
#endif

#ifndef LOGGER_BUFFER_SIZE
#define LOGGER_BUFFER_SIZE 512
#endif

/**
 * Initialize the DMA-based UART logger
 * Returns: 0 on success, -1 on error
 */
int loggerInit(void);

/**
 * Non-blocking log function (printf-style)
 * If DMA is busy or buffer is full, message may be dropped
 * Input: format string and variable arguments
 */
void loggerPrintf(const char *format, ...) __attribute__((format(printf, 1, 2)));

/**
 * Check if the logger DMA is currently busy
 * Returns: true if busy, false if ready for new data
 */
bool loggerIsBusy(void);

/**
 * Wait for all pending DMA transfers to complete
 */
void loggerFlush(void);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */
