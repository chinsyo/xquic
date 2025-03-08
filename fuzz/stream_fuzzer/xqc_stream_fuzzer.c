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
    
    xqc_connection_t *conn = xqc_client_connect(ctx.engine, &dcid, &scid, NULL, 0, "test", 4, NULL, NULL);
    if (conn == NULL) {
        xqc_fuzzer_destroy_ctx(&ctx);
        return 0;
    }
    
    /* 创建一个测试流 */
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn, XQC_STREAM_BIDI);
    if (stream == NULL) {
        xqc_fuzzer_destroy_ctx(&ctx);
        return 0;
    }
    
    /* 将输入数据分割为多个块，模拟流数据处理 */
    size_t chunk_size = size < 10 ? size : size / 10;
    size_t offset = 0;
    
    while (offset < size) {
        size_t current_chunk = (offset + chunk_size <= size) ? chunk_size : (size - offset);
        
        /* 创建一个STREAM帧 */
        xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
        if (packet_out == NULL) {
            break;
        }
        
        /* 生成STREAM帧 */
        xqc_stream_frame_t frame;
        memset(&frame, 0, sizeof(frame));
        frame.stream_id = stream->stream_id;
        frame.offset = offset;
        frame.data_length = current_chunk;
        frame.data = (unsigned char *)data + offset;
        frame.fin = (offset + current_chunk == size) ? 1 : 0;
        
        /* 处理STREAM帧 */
        xqc_int_t ret = xqc_process_stream_frame(conn, &frame);
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