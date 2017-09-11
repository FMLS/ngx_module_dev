#ifndef _NGX_HTTP_ECHO_H_INCLUDED_
#define _NGX_HTTP_ECHO_H_INCLUDED_

typedef struct {
    ngx_str_t     m_str;

} ngx_http_echo_conf_t;


typedef struct {
    ngx_http_status_t status;
} ngx_http_echo_ctx_t;

#endif
