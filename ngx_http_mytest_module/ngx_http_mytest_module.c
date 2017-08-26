#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_mytest_module.h"

void ngx_pool_cleanup_file_m(void *data);
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);
static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t mytest_process_status_line(ngx_http_request_t *r);
static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r);
static char* ngx_http_mytest_merge_loc_conf(ngx_conf_t * cf, void * parent, void *child);
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t * r);

//这个需要自定义
static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};
//自定义配置解析函数
static char* ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mytest_handler;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_mytest_commands[] = {
    { 
        ngx_string("ly_echo"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
        NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,  //store struct params parsed by create_loc_conf
        offsetof(ngx_http_mytest_conf_t, m_str),
        NULL 
    },
    { 
        ngx_string("ly_run"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | 
        NGX_CONF_NOARGS,
        ngx_http_mytest,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL,
    },
    {
        ngx_string("ly_upstream_connect_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, upstream.connect_timeout),
        NULL,
    },
    {
        ngx_string("ly_upstream_send_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, upstream.send_timeout),
        NULL,
    },
    {
        ngx_string("ly_upstream_read_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mytest_conf_t, upstream.read_timeout),
        NULL,
    },
    ngx_null_command
};

static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mytest_conf_t *mycf;
    mycf = (ngx_http_mytest_conf_t *)ngx_pcalloc(cf->pool, 
            sizeof(ngx_http_mytest_conf_t)); 

    if (mycf == NULL) {
        return NULL;
    }

    mycf->my_flag = NGX_CONF_UNSET;
    mycf->my_num = NGX_CONF_UNSET;
    mycf->my_str_array = NGX_CONF_UNSET_PTR;
    mycf->my_keyval = NULL;
    mycf->my_off = NGX_CONF_UNSET;
    mycf->my_msec = NGX_CONF_UNSET_MSEC;
    mycf->my_sec = NGX_CONF_UNSET;
    mycf->my_size = NGX_CONF_UNSET_SIZE;

    mycf->upstream.connect_timeout = 60000;
    mycf->upstream.send_timeout    = 60000;
    mycf->upstream.read_timeout    = 60000;
    mycf->upstream.store_access    = 0600;
    mycf->upstream.bufs.num = 8;
    mycf->upstream.bufs.size = ngx_pagesize;
    mycf->upstream.buffer_size = 2 * ngx_pagesize;
    mycf->upstream.busy_buffers_size = 2 * ngx_pagesize;
    mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;
    mycf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    mycf->upstream.buffering       = 0;


    return mycf;
}

static ngx_http_module_t ngx_http_mytest_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_mytest_create_loc_conf,
    //NULL,
    ngx_http_mytest_merge_loc_conf,
};

ngx_module_t ngx_http_mytest_module = {
    NGX_MODULE_V1,
    &ngx_http_mytest_module_ctx,
    ngx_http_mytest_commands,
    NGX_HTTP_MODULE,

    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,

    NGX_MODULE_V1_PADDING
};

/*获取ly_echo 指令字符串*/
//static ngx_str_t get_ly_echo_set(ngx_http_request_t *r) {
//
//    ngx_http_mytest_conf_t *elcf;
//    elcf = ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
//
//    return elcf->m_str;
//}

//static ngx_chain_t get_echo_body_out(ngx_http_request_t *r, ngx_int_t *content_len,
//                                        unsigned last) {
//
//    ngx_buf_t *buf;
//    ngx_http_mytest_conf_t *elcf;
//    elcf = ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
//    ngx_str_t echo_str = elcf->m_str;
//    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "m_str: %*s", echo_str.len, echo_str.data);
//    buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
//    //if (buf == NULL) {
//    //    return NGX_HTTP_INTERNAL_SERVER_ERROR;
//    //}
//    ngx_memcpy(buf->pos, echo_str.data, echo_str.len);
//    buf->last = buf->pos + echo_str.len;
//    buf->memory = 1;
//    buf->last_buf = last;
//
//    *content_len += echo_str.len;
//
//    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "buf->pos:%*s",
//                    echo_str.len, buf->pos);
//
//    ngx_chain_t out;
//    out.buf = buf;
//    out.next = NULL;
//
//    return out;
//}

/*获取测试字符串body*/
//static ngx_chain_t get_test_str_out(ngx_http_request_t *r, ngx_int_t *content_len,
//                                    unsigned last) {
//
//    ngx_buf_t *buf;
//    ngx_str_t response = ngx_string("This is liuyang's test module");
//    buf = ngx_create_temp_buf(r->pool, response.len);
//    //if (buf == NULL) {
//    //    return NGX_HTTP_INTERNAL_SERVER_ERROR;
//    //}
//
//    ngx_memcpy(buf->pos, response.data, response.len);
//    buf->last = buf->pos + response.len;
//    buf->last_buf = last;
//    
//    *content_len += response.len;
//
//    ngx_chain_t out;
//    out.buf = buf;
//    out.next = NULL;
//
//    return out;
//}

/*获取文件body*/
//static ngx_chain_t get_file_body_out(ngx_http_request_t *r, ngx_int_t *content_len,
//                                        unsigned last) {
//
//    ngx_buf_t *file_buf;
//    file_buf = ngx_palloc(r->pool, sizeof(ngx_buf_t));
//    u_char* file_name = (u_char*) "/tmp/test.txt";
//    file_buf->in_file = 1;
//    file_buf->file = ngx_palloc(r->pool, sizeof(ngx_file_t));
//    file_buf->file->fd   = ngx_open_file(file_name, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);
//    file_buf->file->log  = r->connection->log;
//    file_buf->file->name.data = file_name;
//    file_buf->file->name.len  = strlen((const char*)file_name);
//
//    //if (file_buf->file->fd <= 0) {
//    //    return NGX_HTTP_NOT_FOUND;
//    //}
//
//    //if (ngx_file_info(file_name, &file_buf->file->info) == NGX_FILE_ERROR) {
//    //     return NGX_HTTP_INTERNAL_SERVER_ERROR;
//    //}
//
//    ngx_file_info(file_name, &file_buf->file->info);
//
//    file_buf->file_pos = 0;
//    file_buf->file_last = file_buf->file->info.st_size;
//    file_buf->last_buf = last;
//
//    *content_len += file_buf->file->info.st_size;
//    /*清理文件句柄*/
//    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool,
//                                sizeof(ngx_pool_cleanup_file_t));
//    //if (cln == NULL) {
//    //    return  NGX_ERROR;
//    //}
//    cln->handler = ngx_pool_cleanup_file_m;
//    ngx_pool_cleanup_file_t *clnf = cln->data;
//    clnf->fd   = file_buf->file->fd;
//    clnf->name = file_buf->file->name.data;
//    clnf->log  = r->pool->log;
//
//    ngx_chain_t out;
//    out.buf = file_buf;
//    out.next = NULL;
//
//    return out;
//}

//static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r){
//    if (! (r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) ) {
//        return NGX_HTTP_NOT_ALLOWED;
//    }
//
//    ngx_int_t rc = ngx_http_discard_request_body(r);
//    if( rc != NGX_OK ) {
//        return rc;
//    }
//
//    ngx_int_t temp_len = 0;
//    ngx_int_t content_len = 0;
//
//    //ngx_chain_t out_str, out_echo;//, out_file;
//    //out_str = get_test_str_out(r, &temp_len, 0);
//    //out_str.next = &out_echo;
//    //content_len += temp_len;
//
//    //out_echo = get_echo_body_out(r, &temp_len, 1);
//    //out_echo.next = NULL;
//    //content_len += temp_len;
//
//    //out_file = get_file_body_out(r, &temp_len, 1);
//    //out_echo.next = NULL;
//    //content_len += temp_len;
//
//    ngx_chain_t out_echo, out_file;
//    ngx_http_mytest_conf_t *elcf = ngx_http_get_module_loc_conf(r,ngx_http_mytest_module);
//    ngx_buf_t *b = ngx_palloc(r->pool, sizeof(ngx_buf_t));
//    b->pos = elcf->m_str.data;
//    b->last = elcf->m_str.data + (elcf->m_str.len);
//    b->memory = 1;
//    b->last_buf = 0;
//    content_len += elcf->m_str.len;
//
//    out_echo.buf = b;
//    out_echo.next = &out_file;
//
//    out_file = get_file_body_out(r, &temp_len, 1);
//    out_file.next = NULL;
//    content_len += temp_len; 
//
//    /*头部设置 注意content-length的设置*/
//    ngx_str_t type = ngx_string("text/plain");
//    r->headers_out.status = NGX_HTTP_OK;
//    r->headers_out.content_length_n = content_len;
//    r->headers_out.content_type = type;
//
//    /*设置自定义header头*/
//    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
//    if (h == NULL) {
//        return NGX_ERROR;
//    }
//
//    h->hash = 1;
//    h->key.len = sizeof("TestHeader") - 1;
//    h->key.data = (u_char*) "TestHeader";
//    h->value.len = sizeof("Liuyang") - 1;
//    h->value.data = (u_char*) "Liuyang";
//
//    /*发送头部*/
//    rc = ngx_http_send_header(r);
//    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
//        return rc;
//    }
//
//    /*发送body*/
//    return ngx_http_output_filter(r, &out_echo);
//}

static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r) {
    ngx_http_mytest_ctx_t *myctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (myctx == NULL) {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
        if (myctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, myctx, ngx_http_mytest_module);
    }
    
    //上下文与请求关联
    if (ngx_http_upstream_create(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }

    ngx_http_mytest_conf_t *mycf = (ngx_http_mytest_conf_t* )ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
    ngx_http_upstream_t *u = r->upstream;
    u->conf = &mycf->upstream; //必须设置 否则进程崩溃
    u->buffering = mycf->upstream.buffering;
    u->resolved = (ngx_http_upstream_resolved_t*)ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {

    }

    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char*) "www.csdn.net");
    if (pHost == NULL) {

    }
    //访问上游服务器的80端口
    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t)80);
    char* pDmsIP = inet_ntoa(*(struct in_addr*)(pHost->h_addr_list[0]));
    backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backendServer.data = (u_char*)pDmsIP;
    myctx->backendServer.len = strlen(pDmsIP);

    //将地址设置到resolved成员中
    u->resolved->sockaddr = (struct sockaddr*)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1; //地址个数
    u->resolved->port = htons((in_port_t)80);
    //设置回调方法
    u->create_request = mytest_upstream_create_request;
    u->process_header = mytest_process_status_line;
    u->finalize_request = mytest_upstream_finalize_request;
    //引用计数+1
    r->main->count++;
    //启动upstream机制
    ngx_http_upstream_init(r);
    //框架暂停执行下一阶段
    return NGX_DONE;
}

void ngx_pool_cleanup_file_m(void *data) {
    ngx_pool_cleanup_file_t *c = data;
    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d", c->fd);
    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                        ngx_close_file_n"\"%s\" failed", c->name);
    }
}

static ngx_int_t mytest_upstream_create_request(ngx_http_request_t * r) {

    static ngx_str_t backendQueryLine = 
        ngx_string("GET / HTTP/1.1\r\nHOST: www.csdn.net\r\nConnection: close\r\n\r\n");

    //ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;
    //ngx_int_t queryLineLen = backendQueryLine.len + r->args.len;
    ngx_int_t queryLineLen = backendQueryLine.len;// + r->args.len;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->last = b->pos + queryLineLen;
    //ngx_snprintf(b->pos, queryLineLen,
    //    (char*)backendQueryLine.data, &r->args);
    ngx_memcpy(b->pos, backendQueryLine.data, backendQueryLine.len);
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL) {
        return NGX_ERROR;
    }
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;
    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    r->header_hash = 1;
        
    return NGX_OK;
}

static char* ngx_http_mytest_merge_loc_conf(ngx_conf_t * cf, void * parent, void *child) {
    ngx_http_mytest_conf_t *prev = (ngx_http_mytest_conf_t *)parent;
    ngx_http_mytest_conf_t *conf = (ngx_http_mytest_conf_t *)child;

    ngx_hash_init_t  hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream,
            ngx_http_proxy_hide_headers, &hash) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t mytest_upstream_process_header(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_table_elt_t *h;
    ngx_http_upstream_header_t *hh;
    ngx_http_upstream_main_conf_t *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    //循环解析所有http头
    for(;;) {
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        if (rc == NGX_OK) {
            //向headers_in.headers链表中添加http头
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            //必须在内存池中分配存放HTTP头部的内存空间
            h->key.data = ngx_pnalloc(r->pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }
        //解析完成头部了
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.server == NULL) {

            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                        "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

/*解析http响应头*/
static ngx_int_t mytest_process_status_line(ngx_http_request_t *r) {
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;
    ngx_http_mytest_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    u = r->upstream;
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    if (rc == NGX_AGAIN) {
        return rc;
    }
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream end no valid HTTP/1.0 header");
        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        return NGX_OK;
    }

    if (u->state) {
        u->state->status = ctx->status.code;
    }
    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;
    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);
    u->process_header = mytest_upstream_process_header;

    return mytest_upstream_process_header(r);
}

static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
                    "mytest_upstream_finalize_request");
}
