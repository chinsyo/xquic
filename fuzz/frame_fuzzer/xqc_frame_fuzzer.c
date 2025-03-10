/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "../common/xqc_fuzzer_common.h"

/* 帧模糊测试入口函数 */
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
    
    /* 创建一个数据包 */
    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_fuzzer_destroy_ctx(&ctx);
        return 0;
    }
    
    /* 将输入数据作为帧处理 */
    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pos = (unsigned char *)data;
    packet_in.last = (unsigned char *)data + size;
    
    /* 尝试解析不同类型的帧 */
    xqc_process_frames(conn, &packet_in);
    
    /* 模拟引擎主循环处理 */
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