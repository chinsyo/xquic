/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "../common/xqc_fuzzer_common.h"

/* 数据包模糊测试入口函数 */
int 
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* 限制输入大小，避免过大的输入 */
    if (size == 0 || size > XQC_FUZZER_MAX_INPUT_SIZE) {
        return 0;
    }
    
    /* 初始化模糊测试上下文 */
    xqc_fuzzer_ctx_t ctx;
    if (xqc_fuzzer_init_ctx(&ctx, XQC_ENGINE_SERVER) != XQC_OK) {
        return 0;
    }
    
    /* 创建一个虚拟的客户端地址 */
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    client_addr.sin_port = htons(12345);
    
    /* 处理输入数据作为QUIC数据包 */
    xqc_engine_packet_process(ctx.engine, (const unsigned char *)data, size, 
                             (struct sockaddr *)&client_addr, sizeof(client_addr), 
                             xqc_fuzzer_now(), NULL);
    
    /* 模拟引擎主循环处理 */
    xqc_engine_main_logic(ctx.engine);
    
    /* 销毁模糊测试上下文 */
    xqc_fuzzer_destroy_ctx(&ctx);
    
    return 0;
}

/* 初始化函数 - 可选，用于设置持久状态或初始语料库 */
int 
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    /* 可以在这里设置全局初始化 */
    return 0;
}