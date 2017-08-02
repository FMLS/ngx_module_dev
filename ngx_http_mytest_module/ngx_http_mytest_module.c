#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


void ngx_pool_cleanup_file_m(void *data);

static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r){
    if (! (r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) ) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_int_t rc = ngx_http_discard_request_body(r);
    if( rc != NGX_OK ) {
        return rc;
    }

    ngx_str_t type = ngx_string("text/plain");
    //ngx_str_t response = ngx_string("This is liuyang's test module");
    //ngx_str_t response2 = ngx_string("this is the second buf");

    /*body设置*/
    //ngx_buf_t *b;
    //b = ngx_create_temp_buf(r->pool, response.len);
    //if (b == NULL) {
    //    return NGX_HTTP_INTERNAL_SERVER_ERROR;
    //}

    //ngx_memcpy(b->pos, response.data, response.len);
    //b->last = b->pos + response.len;


    //ngx_buf_t *c;
    //c = ngx_create_temp_buf(r->pool, response2.len);
    //ngx_memcpy(c->pos, response2.data, response2.len);
    //c->last = c->pos + response2.len;
    //c->last_buf = 1;

    //ngx_chain_t out1;
    //out1.buf = c;
    //out1.next = NULL;

    //ngx_chain_t out;
    //out.buf = b;
    //out.next = &out1;

    /*读文件*/
    ngx_buf_t *file_buf;
    file_buf = ngx_palloc(r->pool, sizeof(ngx_buf_t));
    u_char* file_name = (u_char*) "/Users/liuyang/test.txt";
    file_buf->in_file = 1;
    file_buf->file = ngx_palloc(r->pool, sizeof(ngx_file_t));
    file_buf->file->fd   = ngx_open_file(file_name, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);
    file_buf->file->log  = r->connection->log;
    file_buf->file->name.data = file_name;
    file_buf->file->name.len  = strlen((const char*)file_name);

    if (file_buf->file->fd <= 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (ngx_file_info(file_name, &file_buf->file->info) == NGX_FILE_ERROR) {
         return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    file_buf->file_pos = 0;
    file_buf->file_last = file_buf->file->info.st_size;

    /*清理文件句柄*/
    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool,
                                sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        return  NGX_ERROR;
    }
    cln->handler = ngx_pool_cleanup_file_m;
    ngx_pool_cleanup_file_t *clnf = cln->data;
    clnf->fd   = file_buf->file->fd;
    clnf->name = file_buf->file->name.data;
    clnf->log  = r->pool->log;

    /*头部设置*/
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = file_buf->file->info.st_size;
    r->headers_out.content_type = type;

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

    ngx_chain_t out;
    out.buf  = file_buf;
    out.next = NULL;

    /*发送body*/
    return ngx_http_output_filter(r, &out);
}

void ngx_pool_cleanup_file_m(void *data) {
    ngx_pool_cleanup_file_t *c = data;
    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d", c->fd);
    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                        ngx_close_file_n"\"%s\" failed", c->name);
    }
}

static char* ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mytest_handler;

    return NGX_CONF_OK;
}


static ngx_command_t ngx_http_mytest_commands[] = {
    { ngx_string("mytest"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_NOARGS,
      ngx_http_mytest,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_mytest_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
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

