/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_fuzzer_common.h"
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
// #include "src/common/xqc_random.h"

/* 获取当前时间戳（微秒） */
xqc_usec_t 
xqc_fuzzer_now()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

/* 写入回调函数 - 模糊测试中不实际发送数据 */
ssize_t 
xqc_fuzzer_write_callback(const unsigned char *buf, size_t size, 
                          const struct sockaddr *peer_addr,
                          socklen_t peer_addrlen, void *conn_user_data)
{
    /* 在模糊测试中，我们不需要实际发送数据 */
    return size;
}

/* 连接创建回调函数 */
int 
xqc_fuzzer_conn_create_callback(xqc_connection_t *conn, const xqc_cid_t *cid, 
                               uint64_t path_id, void *user_data)
{
    xqc_fuzzer_ctx_t *ctx = (xqc_fuzzer_ctx_t *)user_data;
    
    /* 保存连接ID */
    memcpy(&ctx->cid, cid, sizeof(xqc_cid_t));
    
    return 0;
}

/* 连接关闭回调函数 */
void 
xqc_fuzzer_conn_close_callback(const xqc_cid_t *cid, uint64_t path_id, void *user_data)
{
    return;
}

/* 创建传输层回调函数 */
xqc_transport_callbacks_t transport_cbs = {
    .write_socket = xqc_fuzzer_write_callback,
    .path_created_notify = xqc_fuzzer_conn_create_callback,
    .path_removed_notify = xqc_fuzzer_conn_close_callback,
};

/* 设置定时器回调函数 - 模糊测试中不需要实际的定时器 */
void 
xqc_fuzzer_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    /* 在模糊测试中，我们不需要实际的定时器 */
}

/* 初始化模糊测试上下文 */
xqc_int_t 
xqc_fuzzer_init_ctx(xqc_fuzzer_ctx_t *ctx, xqc_engine_type_t engine_type)
{
    if (ctx == NULL) {
        return -XQC_EPARAM;
    }
    
    memset(ctx, 0, sizeof(xqc_fuzzer_ctx_t));
    
    /* 打开日志文件 */
    ctx->log_fd = open("/dev/null", O_WRONLY);
    if (ctx->log_fd < 0) {
        return -XQC_EFATAL;
    }
    
    /* 创建引擎配置 */
    xqc_engine_ssl_config_t ssl_config;
    memset(&ssl_config, 0, sizeof(ssl_config));
    
    /* 设置证书和私钥（仅服务端需要） */
    if (engine_type == XQC_ENGINE_SERVER) {
        ssl_config.private_key_file = "./server.key";
        ssl_config.cert_file = "./server.crt";
    }
    
    /* 创建引擎回调函数 */
    xqc_engine_callback_t callback = {
        .log_callbacks = {
            .xqc_log_write_err = NULL,
            .xqc_log_write_stat = NULL
        },
        .set_event_timer = xqc_fuzzer_set_event_timer,
    };
    
    /* 创建引擎配置 */
    xqc_config_t engine_config;
    memset(&engine_config, 0, sizeof(engine_config));
    
    /* 创建引擎 */
    ctx->engine = xqc_engine_create(engine_type, &engine_config, &ssl_config, &callback, 
                                   &transport_cbs, ctx);
    if (ctx->engine == NULL) {
        close(ctx->log_fd);
        return -XQC_EFATAL;
    }
    
    ctx->initialized = 1;
    return XQC_OK;
}

/* 生成随机字节 */
void
xqc_random_bytes(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return;
    }
    
    /* 使用xquic的随机数生成函数 */
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(random() & 0xFF);
    }
}

/* 销毁模糊测试上下文 */
void 
xqc_fuzzer_destroy_ctx(xqc_fuzzer_ctx_t *ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return;
    }
    
    /* 销毁引擎 */
    if (ctx->engine) {
        xqc_engine_destroy(ctx->engine);
        ctx->engine = NULL;
    }
    
    /* 关闭日志文件 */
    if (ctx->log_fd >= 0) {
        close(ctx->log_fd);
        ctx->log_fd = -1;
    }
    
    ctx->initialized = 0;
}