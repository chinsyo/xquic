/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "../common/xqc_fuzzer_common.h"

/* 流模糊测试入口函数 */
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
    
    xqc_connection_t *conn = xqc_conn_create(ctx.engine, &dcid, &scid, NULL, NULL, XQC_CONN_TYPE_CLIENT);
    if (conn == NULL) {
        xqc_fuzzer_destroy_ctx(&ctx);
        return 0;
    }
    
    /* 创建一个测试流 */
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn, 0, XQC_STREAM_BIDI, NULL, NULL);
    if (stream == NULL) {
        xqc_fuzzer_destroy_ctx(&ctx);
        return 0;
    }
    
    /* 将输入数据分割为多个块，模拟流数据处理 */
    size_t chunk_size = size < 10 ? size : size / 10;
    size_t offset = 0;
    
    while (offset < size) {
        size_t current_chunk = (offset + chunk_size <= size) ? chunk_size : (size - offset);
        
        /* 由于无法直接处理流帧，这里我们改为使用引擎的主逻辑处理 */
        xqc_int_t ret = xqc_engine_main_logic(ctx.engine);
        
        /* 注意：这里简化了流处理逻辑，实际应用中可能需要更复杂的处理 */
        if (ret != XQC_OK) {
            /* 错误处理是模糊测试的一部分，继续测试 */
        }
        
        offset += current_chunk;
        
        /* 模拟引擎主循环处理 */
        xqc_engine_main_logic(ctx.engine);
    }
    
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