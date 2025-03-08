/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_FUZZER_COMMON_H_
#define _XQC_FUZZER_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_frame.h"

/* 最大模糊测试输入大小 */
#define XQC_FUZZER_MAX_INPUT_SIZE 65536

/* 模糊测试引擎上下文 */
typedef struct xqc_fuzzer_ctx_s {
    /* XQUIC引擎 */
    xqc_engine_t *engine;
    
    /* 连接ID */
    xqc_cid_t cid;
    
    /* 日志文件描述符 */
    int log_fd;
    
    /* 是否初始化 */
    int initialized;
    
    /* 当前状态 */
    xqc_conn_state_t state;
    
    /* 缓冲区 */
    unsigned char buf[XQC_FUZZER_MAX_INPUT_SIZE];
    
    /* 缓冲区长度 */
    size_t buf_len;
} xqc_fuzzer_ctx_t;

/**
 * 初始化模糊测试上下文
 * @param ctx 模糊测试上下文
 * @param engine_type 引擎类型（客户端/服务端）
 * @return XQC_OK成功，其他值失败
 */
xqc_int_t xqc_fuzzer_init_ctx(xqc_fuzzer_ctx_t *ctx, xqc_engine_type_t engine_type);

/**
 * 销毁模糊测试上下文
 * @param ctx 模糊测试上下文
 */
void xqc_fuzzer_destroy_ctx(xqc_fuzzer_ctx_t *ctx);

/**
 * 获取当前时间戳（微秒）
 * @return 时间戳
 */
xqc_usec_t xqc_fuzzer_now();

/**
 * 写入回调函数
 */
ssize_t xqc_fuzzer_write_callback(const unsigned char *buf, size_t size, 
                                  const struct sockaddr *peer_addr,
                                  socklen_t peer_addrlen, void *conn_user_data);

/**
 * 创建连接回调函数
 */
int xqc_fuzzer_conn_create_callback(xqc_connection_t *conn, const xqc_cid_t *cid, 
                                   uint64_t path_id, void *user_data);

/**
 * 连接关闭回调函数
 */
void xqc_fuzzer_conn_close_callback(const xqc_cid_t *cid, uint64_t path_id, void *user_data);

/**
 * 设置定时器回调函数
 */
void xqc_fuzzer_set_event_timer(xqc_usec_t wake_after, void *user_data);

#endif /* _XQC_FUZZER_COMMON_H_ */