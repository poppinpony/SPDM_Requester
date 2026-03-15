cmake_minimum_required(VERSION 3.16)
project(spdm_transport C)

set(CMAKE_C_STANDARD 11)

# 只支援 Linux（使用 sysfs 存取 PCIe Config Space）
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "spdm_transport only supports Linux.")
endif()

add_library(spdm_transport SHARED
    src/transport/doe_transport.c
)

target_include_directories(spdm_transport PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# _GNU_SOURCE 確保 pread/pwrite prototype 正確被引入（glibc 需要）
target_compile_definitions(spdm_transport PRIVATE _GNU_SOURCE)

# 輸出到 spdm_tool/transport/ 方便 Python 直接引用
set_target_properties(spdm_transport PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../spdm_tool/transport
    OUTPUT_NAME spdm_transport
)

install(TARGETS spdm_transport LIBRARY DESTINATION lib)
