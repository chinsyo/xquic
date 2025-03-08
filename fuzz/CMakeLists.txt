# XQUIC Fuzzing CMakeLists.txt

cmake_minimum_required(VERSION 3.5)

# 检查是否启用模糊测试
if(NOT ENABLE_FUZZING)
    message(STATUS "Fuzzing tests are disabled. Use -DENABLE_FUZZING=ON to enable.")
    return()
endif()

message(STATUS "Building XQUIC fuzzing tests")

# 设置编译器标志
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=fuzzer,address -g")

# 包含目录
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/common
    ${CMAKE_SOURCE_DIR}/src/transport
    ${CMAKE_SOURCE_DIR}/src/http3
    ${CMAKE_SOURCE_DIR}/src/tls
    ${CMAKE_SOURCE_DIR}/fuzz/common
)

# 添加通用工具库
add_library(xqc_fuzz_common
    common/xqc_fuzzer_common.c
)

# 添加子目录
add_subdirectory(packet_fuzzer)
add_subdirectory(frame_fuzzer)
add_subdirectory(stream_fuzzer)
add_subdirectory(state_fuzzer)
add_subdirectory(h3_fuzzer)

# 创建语料库目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz/corpus/initial)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz/corpus/handshake)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz/corpus/transport)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz/corpus/h3)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz/corpus/packet)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz/corpus/frame)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz/corpus/stream)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz/corpus/state)

# 添加构建目标
add_custom_target(fuzz
    DEPENDS 
        xqc_packet_fuzzer
        xqc_frame_fuzzer
        xqc_stream_fuzzer
        xqc_state_fuzzer
        xqc_h3_fuzzer
    COMMENT "Building all fuzzing targets"
)

# 添加运行目标
add_custom_target(run_fuzz
    DEPENDS
        run_packet_fuzzer
        run_frame_fuzzer
        run_stream_fuzzer
        run_state_fuzzer
        run_h3_fuzzer
    COMMENT "Running all fuzzing targets"
)