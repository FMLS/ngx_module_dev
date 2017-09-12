#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_echo_module.h"

static void* ngx_http_echo_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_echo_handler(ngx_http_request_t *r);
static char* ngx_http_conf_echo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_echo_module_commands[] = {
    { 
        ngx_string("echo"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
        NGX_CONF_TAKE1,
        ngx_http_conf_echo,
        NGX_HTTP_LOC_CONF_OFFSET,  //store struct params parsed by create_loc_conf
        offsetof(ngx_http_echo_conf_t, m_str),
        NULL 
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_echo_module_ctx = {
    NULL, 
    NULL,
    
    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_echo_create_loc_conf,
    NULL
};

/*定义本模块*/
ngx_module_t ngx_http_echo_module = {
    NGX_MODULE_V1,
    &ngx_http_echo_module_ctx, //必须是 ngx_http_module_t类型
    ngx_http_echo_module_commands,
    NGX_HTTP_MODULE,

//七个回调方法
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,

    NGX_MODULE_V1_PADDING
};

static char* 
ngx_http_conf_echo(ngx_conf_t *cf, ngx_command_t *cmd, 
                                    void *conf) {

    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_echo_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

static void*
ngx_http_echo_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_echo_conf_t *conf;
    conf = ngx_palloc(cf->pool, sizeof(ngx_http_echo_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->m_str.len = 0;
    conf->m_str.data = NULL;
    return conf;
}

static ngx_int_t ngx_http_echo_handler(ngx_http_request_t *r) {
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_t type = ngx_string("text/plain");
    ngx_http_echo_conf_t *echo_conf;
    echo_conf = ngx_http_get_module_loc_conf(r, ngx_http_echo_module);
    ngx_str_t response = echo_conf->m_str;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = response.len;
    r->headers_out.content_type = type;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_buf_t *b;
    b = ngx_create_temp_buf(r->pool, response.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, response.data, response.len);
    b->last = b->pos + response.len;
    b->last_buf = 1;
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
    
    return ngx_http_output_filter(r, &out);
}
