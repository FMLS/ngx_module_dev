#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_mytest_module.h"

void ngx_pool_cleanup_file_m(void *data);
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);

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
    NULL,
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
static ngx_chain_t get_file_body_out(ngx_http_request_t *r, ngx_int_t *content_len,
                                        unsigned last) {

    ngx_buf_t *file_buf;
    file_buf = ngx_palloc(r->pool, sizeof(ngx_buf_t));
    u_char* file_name = (u_char*) "/tmp/test.txt";
    file_buf->in_file = 1;
    file_buf->file = ngx_palloc(r->pool, sizeof(ngx_file_t));
    file_buf->file->fd   = ngx_open_file(file_name, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);
    file_buf->file->log  = r->connection->log;
    file_buf->file->name.data = file_name;
    file_buf->file->name.len  = strlen((const char*)file_name);

    //if (file_buf->file->fd <= 0) {
    //    return NGX_HTTP_NOT_FOUND;
    //}

    //if (ngx_file_info(file_name, &file_buf->file->info) == NGX_FILE_ERROR) {
    //     return NGX_HTTP_INTERNAL_SERVER_ERROR;
    //}

    ngx_file_info(file_name, &file_buf->file->info);

    file_buf->file_pos = 0;
    file_buf->file_last = file_buf->file->info.st_size;
    file_buf->last_buf = last;

    *content_len += file_buf->file->info.st_size;
    /*清理文件句柄*/
    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool,
                                sizeof(ngx_pool_cleanup_file_t));
    //if (cln == NULL) {
    //    return  NGX_ERROR;
    //}
    cln->handler = ngx_pool_cleanup_file_m;
    ngx_pool_cleanup_file_t *clnf = cln->data;
    clnf->fd   = file_buf->file->fd;
    clnf->name = file_buf->file->name.data;
    clnf->log  = r->pool->log;

    ngx_chain_t out;
    out.buf = file_buf;
    out.next = NULL;

    return out;
}

static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r){
    if (! (r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) ) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_int_t rc = ngx_http_discard_request_body(r);
    if( rc != NGX_OK ) {
        return rc;
    }

    ngx_int_t temp_len = 0;
    ngx_int_t content_len = 0;

    //ngx_chain_t out_str, out_echo;//, out_file;
    //out_str = get_test_str_out(r, &temp_len, 0);
    //out_str.next = &out_echo;
    //content_len += temp_len;

    //out_echo = get_echo_body_out(r, &temp_len, 1);
    //out_echo.next = NULL;
    //content_len += temp_len;

    //out_file = get_file_body_out(r, &temp_len, 1);
    //out_echo.next = NULL;
    //content_len += temp_len;

    ngx_chain_t out_echo, out_file;
    ngx_http_mytest_conf_t *elcf = ngx_http_get_module_loc_conf(r,ngx_http_mytest_module);
    ngx_buf_t *b = ngx_palloc(r->pool, sizeof(ngx_buf_t));
    b->pos = elcf->m_str.data;
    b->last = elcf->m_str.data + (elcf->m_str.len);
    b->memory = 1;
    b->last_buf = 0;
    content_len += elcf->m_str.len;

    out_echo.buf = b;
    out_echo.next = &out_file;

    out_file = get_file_body_out(r, &temp_len, 1);
    out_file.next = NULL;
    content_len += temp_len; 

    /*头部设置 注意content-length的设置*/
    ngx_str_t type = ngx_string("text/plain");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = content_len;
    r->headers_out.content_type = type;

    /*设置自定义header头*/
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = sizeof("TestHeader") - 1;
    h->key.data = (u_char*) "TestHeader";
    h->value.len = sizeof("Liuyang") - 1;
    h->value.data = (u_char*) "Liuyang";

    /*发送头部*/
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    /*发送body*/
    return ngx_http_output_filter(r, &out_echo);
}

void ngx_pool_cleanup_file_m(void *data) {
    ngx_pool_cleanup_file_t *c = data;
    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d", c->fd);
    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                        ngx_close_file_n"\"%s\" failed", c->name);
    }
}
