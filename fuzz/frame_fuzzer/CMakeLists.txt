# 帧模糊测试器构建配置

# 添加可执行文件
add_executable(xqc_frame_fuzzer
    xqc_frame_fuzzer.c
)

# 链接依赖库
target_link_libraries(xqc_frame_fuzzer
    xqc_fuzz_common
    xquic
)

# 设置输出目录
set_target_properties(xqc_frame_fuzzer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz"
)

# 添加测试目标
add_custom_target(run_frame_fuzzer
    COMMAND xqc_frame_fuzzer -max_len=4096 -timeout=10 ${CMAKE_BINARY_DIR}/fuzz/corpus/frame/
    DEPENDS xqc_frame_fuzzer
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running frame fuzzer"
)