# 数据包模糊测试器构建配置

# 添加可执行文件
add_executable(xqc_packet_fuzzer
    xqc_packet_fuzzer.c
)

# 链接依赖库
target_link_libraries(xqc_packet_fuzzer
    xqc_fuzz_common
    xquic
)

# 设置输出目录
set_target_properties(xqc_packet_fuzzer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz"
)

# 添加测试目标
add_custom_target(run_packet_fuzzer
    COMMAND xqc_packet_fuzzer -max_len=4096 -timeout=10 ${CMAKE_BINARY_DIR}/fuzz/corpus/packet/
    DEPENDS xqc_packet_fuzzer
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running packet fuzzer"
)