cmake_minimum_required(VERSION 3.13)

project(pi_pico_radio_mac C ASM)

add_library(pi_pico_radio_mac INTERFACE)

target_sources(pi_pico_radio_mac INTERFACE
	src/mac_radio.c
)

target_include_directories(pi_pico_radio_mac INTERFACE
	src
)
