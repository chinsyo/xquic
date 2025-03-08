# HTTP/3模糊测试器构建配置

# 添加可执行文件
add_executable(xqc_h3_fuzzer
    xqc_h3_fuzzer.c
)

# 链接依赖库
target_link_libraries(xqc_h3_fuzzer
    xqc_fuzz_common
    xquic
)

# 设置输出目录
set_target_properties(xqc_h3_fuzzer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz"
)

# 添加测试目标
add_custom_target(run_h3_fuzzer
    COMMAND xqc_h3_fuzzer -max_len=4096 -timeout=10 ${CMAKE_BINARY_DIR}/fuzz/corpus/h3/
    DEPENDS xqc_h3_fuzzer
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running HTTP/3 fuzzer"
)