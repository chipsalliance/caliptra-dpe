# Copyright (c) 2023 Google LLC.
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_DPE_MODULE)

zephyr_library()

set(DPE_MODULE_DIR ${ZEPHYR_CURRENT_MODULE_DIR})
set(DPE_ZEPHYR_OVERRIDE_DIR ${ZEPHYR_CURRENT_CMAKE_DIR})
set(DPE_BINARY_DIR ${CMAKE_BINARY_DIR}/modules/dpe)
set(DPE_LIB_BINARY_PATH ${DPE_BINARY_DIR}/thumbv7em-none-eabi/release/libdpe.a)

# Enable ExternalProject CMake module for the DPE Rust library.
include(ExternalProject)

# Add dpe as a CMake target
ExternalProject_Add(
    dpe_lib
    PREFIX ${DPE_BINARY_DIR}
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${DPE_BINARY_DIR} cargo build --lib --release --target=thumbv7em-none-eabi --features=zephyr_os
    BUILD_ALWAYS TRUE
    SOURCE_DIR "${DPE_MODULE_DIR}/dpe"
    BINARY_DIR "${DPE_MODULE_DIR}/dpe"
    BUILD_BYPRODUCTS ${DPE_LIB_BINARY_PATH}
    INSTALL_COMMAND ""
    LOG_BUILD ON)

zephyr_link_libraries(${DPE_LIB_BINARY_PATH})
zephyr_library_include_directories(${DPE_MODULE_DIR}/c/include)
zephyr_library_sources(${DPE_ZEPHYR_OVERRIDE_DIR}/empty.c)

endif() # CONFIG_DPE_MODULE
