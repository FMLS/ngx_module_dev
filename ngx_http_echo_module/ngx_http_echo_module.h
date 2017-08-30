#ifndef _NGX_HTTP_ECHO_H_INCLUDED_
#define _NGX_HTTP_ECHO_H_INCLUDED_

typedef struct {
    ngx_str_t     m_str;
    ngx_int_t     my_num;
    ngx_flag_t    my_flag;
    size_t        my_size;
    ngx_array_t*  my_str_array;
    ngx_array_t*  my_keyval;
    off_t         my_off;
    ngx_msec_t    my_msec;
    time_t        my_sec;
    ngx_bufs_t    my_bufs;
    ngx_uint_t    my_enum_seq;
    ngx_uint_t    my_bitmask;
    ngx_uint_t    my_access;
    ngx_path_t*   my_path;

    ngx_http_upstream_conf_t upstream;
} ngx_http_echo_conf_t;


typedef struct {
    ngx_http_status_t status;
    ngx_str_t backendServer;
} ngx_http_echo_ctx_t;

#endif
