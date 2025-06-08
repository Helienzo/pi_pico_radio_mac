# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.1.1)
set(toolchainVersion 13_3_Rel1)
set(picotoolVersion 2.1.1)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico2 CACHE STRING "Board type")

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

project(radio_mac_auto_high_throughput C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()
FetchContent_Declare(
  rp2x_rfm69
  GIT_REPOSITORY https://github.com/Helienzo/rp2x_rfm69.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(rp2x_rfm69)

FetchContent_Declare(
  c_buffer
  GIT_REPOSITORY https://github.com/Helienzo/c_buffer.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(c_buffer)

FetchContent_Declare(
  pi_pico_gpio_hal
  GIT_REPOSITORY https://github.com/Helienzo/pi_pico_gpio_hal.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(pi_pico_gpio_hal)

FetchContent_Declare(
  pico_bootsel_button
  GIT_REPOSITORY https://github.com/Helienzo/pico_bootsel_button.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(pico_bootsel_button)

FetchContent_Declare(
  static_queue  
  GIT_REPOSITORY https://github.com/Helienzo/static_queue.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(static_queue)

FetchContent_Declare(
  static_pool
  GIT_REPOSITORY https://github.com/Helienzo/static_pool.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(static_pool)

FetchContent_Declare(
  static_map
  GIT_REPOSITORY https://github.com/Helienzo/static_map.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(static_map)

FetchContent_Declare(
  rfm69_radio_hal
  GIT_REPOSITORY https://github.com/Helienzo/rfm69_radio_hal.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(rfm69_radio_hal)

FetchContent_Declare(
  pi_pico_radio_phy
  GIT_REPOSITORY https://github.com/Helienzo/pi_pico_radio_phy.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(pi_pico_radio_phy)

set(MODULE_PATH "../..")
add_subdirectory(${MODULE_PATH} libs/pi_pico_radio_mac)

# Add executable. Default name is the project name, version 0.1

add_executable(radio_mac_auto_high_throughput radio_mac_auto_high_throughput.c )

pico_set_program_name(radio_mac_auto_high_throughput "radio_mac_auto_high_throughput")
pico_set_program_version(radio_mac_auto_high_throughput "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(radio_mac_auto_high_throughput 0)
pico_enable_stdio_usb(radio_mac_auto_high_throughput 1)

# Set phy and hal library configurations
target_compile_definitions(radio_mac_auto_high_throughput PRIVATE
    HAL_RADIO_MAX_BUFFER_SIZE=255
    PHY_RADIO_SLOT_TIME_US=8000
    PHY_RADIO_GUARD_TIME_US=500
    PHY_RADIO_PACKET_GUARD_TIME_US=20
    PHY_RADIO_SUPERFRAME_LEN=3
    PHY_RADIO_SYNC_TIMEOUT=9
    PHY_RADIO_BIT_RATE=HAL_RADIO_BITRATE_250
)

# Add the standard library to the build
target_link_libraries(radio_mac_auto_high_throughput
        pico_stdlib)

# Add the standard include files to the build
target_include_directories(radio_mac_auto_high_throughput PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
)

# Add any user requested libraries
target_link_libraries(radio_mac_auto_high_throughput 
        hardware_spi
        hardware_pwm
        rp2x_rfm69_lib
        c_buffer
        pi_pico_gpio_hal
        pico_bootsel_button
        static_queue
        static_pool
        static_map
        rfm69_radio_hal
        pi_pico_radio_phy
        pi_pico_radio_mac
        )

if (PICO_CYW43_SUPPORTED)
    target_link_libraries(radio_mac_auto_high_throughput pico_cyw43_arch_none)
endif()
    
pico_add_extra_outputs(radio_mac_auto_high_throughput)
