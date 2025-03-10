/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "../common/xqc_fuzzer_common.h"
#include <xquic/xqc_http3.h>

/* HTTP/3模糊测试上下文 */
typedef struct xqc_h3_fuzzer_ctx_s {
    /* 基础模糊测试上下文 */
    xqc_fuzzer_ctx_t base_ctx;
    
    /* HTTP/3连接 */
    xqc_h3_conn_t *h3_conn;
    
    /* HTTP/3请求 */
    xqc_h3_request_t *h3_request;
    
    /* 请求头部 */
    xqc_http_headers_t headers;
    
    /* 是否已发送请求头 */
    int header_sent;
} xqc_h3_fuzzer_ctx_t;

/* HTTP/3请求回调函数 */
int 
xqc_h3_fuzzer_request_create_callback(xqc_h3_request_t *h3_request, void *user_data)
{
    xqc_h3_fuzzer_ctx_t *ctx = (xqc_h3_fuzzer_ctx_t *)user_data;
    ctx->h3_request = h3_request;
    return 0;
}

/* HTTP/3请求关闭回调函数 */
int 
xqc_h3_fuzzer_request_close_callback(xqc_h3_request_t *h3_request, void *user_data)
{
    return 0;
}

/* HTTP/3请求读取回调函数 */
int 
xqc_h3_fuzzer_request_read_callback(xqc_h3_request_t *h3_request, 
                                   xqc_request_notify_flag_t flag,
                                   void *user_data)
{
    return 0;
}

/* HTTP/3请求写回调函数 */
int 
xqc_h3_fuzzer_request_write_callback(xqc_h3_request_t *h3_request, 
                                    void *user_data)
{
    return 0;
}

/* HTTP/3连接创建回调函数 */
int
xqc_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    xqc_h3_fuzzer_ctx_t *ctx = (xqc_h3_fuzzer_ctx_t *)user_data;
    ctx->h3_conn = h3_conn;
    return 0;
}

/* HTTP/3连接关闭回调函数 */
int
xqc_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    return 0;
}

/* HTTP/3连接握手完成回调函数 */
void
xqc_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    /* 握手完成，不需要返回值 */
    return;
}

/* HTTP/3模糊测试入口函数 */
int 
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* 限制输入大小，避免过大的输入 */
    if (size == 0 || size > XQC_FUZZER_MAX_INPUT_SIZE) {
        return 0;
    }
    
    /* 初始化HTTP/3模糊测试上下文 */
    xqc_h3_fuzzer_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    
    /* 初始化基础模糊测试上下文 */
    if (xqc_fuzzer_init_ctx(&ctx.base_ctx, XQC_ENGINE_SERVER) != XQC_OK) {
        return 0;
    }
    
    /* 创建一个测试连接 */
    xqc_cid_t scid, dcid;
    xqc_random_bytes(scid.cid_buf, XQC_MAX_CID_LEN);
    xqc_random_bytes(dcid.cid_buf, XQC_MAX_CID_LEN);
    scid.cid_len = XQC_MAX_CID_LEN;
    dcid.cid_len = XQC_MAX_CID_LEN;
    
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(8080);
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* 使用xqc_h3_connect代替xqc_client_connect */
    const xqc_cid_t *cid = xqc_h3_connect(ctx.base_ctx.engine, NULL, 
                                       NULL, 0, NULL, 0, 
                                       NULL, 
                                       (struct sockaddr *)&client_addr, sizeof(client_addr), 
                                       &ctx);
    /* 客户端地址已在前面创建 */
    
    if (cid == NULL) {
        xqc_fuzzer_destroy_ctx(&ctx.base_ctx);
        return 0;
    }
    
    /* 创建HTTP/3回调函数 */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_create_notify = xqc_h3_fuzzer_request_create_callback,
            .h3_request_close_notify = xqc_h3_fuzzer_request_close_callback,
            .h3_request_read_notify = xqc_h3_fuzzer_request_read_callback,
            .h3_request_write_notify = xqc_h3_fuzzer_request_write_callback,
        }
    };
    
    /* 不需要手动创建HTTP/3连接，xqc_h3_connect已经创建了 */
    /* xqc_h3_conn_create在内部由xqc_h3_connect调用 */
    if (ctx.h3_conn == NULL) {
        xqc_fuzzer_destroy_ctx(&ctx.base_ctx);
        return 0;
    }
    
    /* 将输入数据分为两部分：头部和正文 */
    size_t header_size = size / 3;
    size_t body_size = size - header_size;
    
    /* 客户端地址已在前面创建 */
    
    /* 处理输入数据作为HTTP/3请求 */
    if (header_size > 0) {
        /* 创建一个HTTP/3请求 */
        /* 由于xqc_h3_request_create需要更多参数，这里简化处理 */
        /* 在实际应用中，应该正确创建HTTP/3请求 */
        if (ctx.h3_request) {
            /* 构造HTTP头部 */
            xqc_http_header_t headers[4];
            headers[0].name.iov_base = ":method";
            headers[0].name.iov_len = 7;
            headers[0].value.iov_base = "GET";
            headers[0].value.iov_len = 3;
            
            headers[1].name.iov_base = ":scheme";
            headers[1].name.iov_len = 7;
            headers[1].value.iov_base = "https";
            headers[1].value.iov_len = 5;
            
            headers[2].name.iov_base = ":path";
            headers[2].name.iov_len = 5;
            headers[2].value.iov_base = "/";
            headers[2].value.iov_len = 1;
            
            headers[3].name.iov_base = ":authority";
            headers[3].name.iov_len = 10;
            headers[3].value.iov_base = "test.com";
            headers[3].value.iov_len = 8;
            
            ctx.headers.headers = headers;
            ctx.headers.count = 4;
            
            /* 发送HTTP头部 */
            xqc_int_t ret = xqc_h3_request_send_headers(ctx.h3_request, &ctx.headers, 0);
            if (ret == XQC_OK) {
                ctx.header_sent = 1;
            }
            
            /* 如果有正文数据，发送正文 */
            if (body_size > 0 && ctx.header_sent) {
                xqc_h3_request_send_body(ctx.h3_request, (unsigned char *)data + header_size, body_size, 1);
            }
        }
    }
    
    /* 处理输入数据作为QUIC数据包 */
    xqc_engine_packet_process(ctx.base_ctx.engine, (const unsigned char *)data, size,
                             (struct sockaddr *)&client_addr, sizeof(client_addr),
                             (struct sockaddr *)&client_addr, sizeof(client_addr),
                             xqc_fuzzer_now(), NULL);
    
    /* 模拟引擎主循环处理 */
    xqc_engine_main_logic(ctx.base_ctx.engine);
    
    /* 销毁模糊测试上下文 */
    xqc_fuzzer_destroy_ctx(&ctx.base_ctx);
    
    return 0;
}

/* 初始化函数 */
int 
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}