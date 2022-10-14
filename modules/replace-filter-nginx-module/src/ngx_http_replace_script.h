
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_HTTP_REPLACE_SCRIPT_H_INCLUDED_
#define _NGX_HTTP_REPLACE_SCRIPT_H_INCLUDED_


#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sregex/sregex.h>


typedef struct {
    ngx_conf_t                 *cf;
    ngx_str_t                  *source;

    ngx_array_t               **lengths;
    ngx_array_t               **values;

    ngx_uint_t                  capture_variables;  /* captures $1, $2, etc */
    ngx_uint_t                  nginx_variables;  /* nginx variables */
    ngx_uint_t                  size;
} ngx_http_replace_script_compile_t;


typedef struct {
    ngx_str_t                   value;
    void                       *lengths;
    void                       *values;
    ngx_uint_t                  capture_variables;
} ngx_http_replace_complex_value_t;


typedef struct {
    ngx_conf_t                      *cf;
    ngx_str_t                       *value;

    ngx_http_replace_complex_value_t    *complex_value;
} ngx_http_replace_compile_complex_value_t;


typedef struct {
    u_char                     *ip;
    u_char                     *pos;

    ngx_str_t                   buf;

    sre_int_t                  *captures;
    ngx_uint_t                  ncaptures;
    ngx_chain_t                *captures_data;

    unsigned                    skip:1;

    ngx_http_request_t         *request;
} ngx_http_replace_script_engine_t;


typedef size_t (*ngx_http_replace_script_code_pt)
    (ngx_http_replace_script_engine_t *e);

typedef size_t (*ngx_http_replace_script_len_code_pt)
    (ngx_http_replace_script_engine_t *e);


typedef struct {
    ngx_http_replace_script_code_pt     code;
    uintptr_t                           len;
} ngx_http_replace_script_copy_code_t;


typedef struct {
    ngx_http_replace_script_code_pt     code;
    uintptr_t                           n;
} ngx_http_replace_script_capture_code_t;


typedef struct {
    ngx_http_replace_script_code_pt     code;
    uintptr_t                           index;
} ngx_http_replace_script_var_code_t;


ngx_int_t ngx_http_replace_compile_complex_value(
    ngx_http_replace_compile_complex_value_t *ccv);
ngx_int_t ngx_http_replace_complex_value(ngx_http_request_t *r,
    ngx_chain_t *captured, sre_uint_t ncaps, sre_int_t *cap,
    ngx_http_replace_complex_value_t *val, ngx_str_t *value);


#endif /* _NGX_HTTP_REPLACE_SCRIPT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
