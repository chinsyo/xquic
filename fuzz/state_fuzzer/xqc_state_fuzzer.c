/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "../common/xqc_fuzzer_common.h"

/* 状态转换模糊测试入口函数 */
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
    
    /* 创建一个测试连接 */
    xqc_cid_t scid, dcid;
    xqc_random_bytes(scid.cid_buf, XQC_MAX_CID_LEN);
    xqc_random_bytes(dcid.cid_buf, XQC_MAX_CID_LEN);
    scid.cid_len = XQC_MAX_CID_LEN;
    dcid.cid_len = XQC_MAX_CID_LEN;
    
    xqc_connection_t *conn = xqc_client_connect(ctx.engine, &dcid, &scid, NULL, 0, "test", 4, NULL, NULL);
    if (conn == NULL) {
        xqc_fuzzer_destroy_ctx(&ctx);
        return 0;
    }
    
    /* 使用输入数据的前几个字节来确定要测试的状态转换序列 */
    uint8_t state_seq[16] = {0};
    size_t seq_len = size < 16 ? size : 16;
    memcpy(state_seq, data, seq_len);
    
    /* 剩余的数据用作数据包内容 */
    const uint8_t *packet_data = data + seq_len;
    size_t packet_size = size - seq_len;
    
    /* 创建一个虚拟的客户端地址 */
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    client_addr.sin_port = htons(12345);
    
    /* 根据状态序列执行不同的操作 */
    for (size_t i = 0; i < seq_len; i++) {
        /* 根据当前字节的值选择操作 */
        switch (state_seq[i] % 5) {
            case 0: /* 处理数据包 */
                if (packet_size > 0) {
                    xqc_engine_packet_process(ctx.engine, 
                                           (const unsigned char *)packet_data, 
                                           packet_size, 
                                           (struct sockaddr *)&client_addr, 
                                           sizeof(client_addr), 
                                           xqc_fuzzer_now(), 
                                           NULL);
                }
                break;
                
            case 1: /* 触发超时 */
                xqc_engine_main_logic(ctx.engine);
                break;
                
            case 2: /* 尝试关闭连接 */
                if (conn) {
                    xqc_conn_close(conn);
                }
                break;
                
            case 3: /* 创建流 */
                if (conn) {
                    xqc_stream_t *stream = xqc_create_stream_with_conn(conn, XQC_STREAM_BIDI);
                    if (stream) {
                        /* 可以在这里对流进行操作 */
                    }
                }
                break;
                
            case 4: /* 发送数据 */
                if (conn) {
                    /* 模拟发送一些数据 */
                    xqc_engine_main_logic(ctx.engine);
                }
                break;
        }
    }
    
    /* 最后再次运行主逻辑，确保所有状态转换都被处理 */
    xqc_engine_main_logic(ctx.engine);
    
    /* 销毁模糊测试上下文 */
    xqc_fuzzer_destroy_ctx(&ctx);
    
    return 0;
}

/* 初始化函数 */
int 
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}